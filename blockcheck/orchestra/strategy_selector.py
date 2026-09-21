"""Справочник стратегий обхода (winws2) и подбор по симптомам.

Стратегии собраны из ``strategy_catalogs\\winws2\\*.txt`` проекта ZapretGUI
(реальные параметры ``--lua-desync``), но приведены к единой схеме нашей
подсистемы: id ``gs_*`` + категория + «сырые» параметры в формате
``serializer.apply_strategy`` (``{add, set, remove}``).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from blockcheck.orchestra.symptom_mapping import FAILURE_TO_SYMPTOM, SYMPTOMS

__all__ = [
    "STRATEGIES",
    "SYMPTOM_TO_STRATEGY",
    "available_strategies",
    "create_strategy_for_failure_type",
    "find_strategy_by_id",
    "rank_recommendations",
]


# --------------------------------------------------------------------------
# Каталог стратегий. parameters — словарь {add: {key: [значения...]},
# set: {key: значение}, remove: [key...]} в терминах serializer.
# --------------------------------------------------------------------------
def _p(*values: str) -> Dict[str, Any]:
    return {"add": {"--lua-desync": list(values)}}


STRATEGIES: List[Dict[str, Any]] = [
    # ── TCP: SNI-фильтрация / TLS-сбросы ────────────────────────────────
    {
        "id": "gs_pass",
        "name": "pass (без изменений)",
        "category": "tcp",
        "label": "stable",
        "description": "Ничего не делает — трафик идёт как есть. Полезен для сверки.",
        "parameters": _p("pass"),
        "symptoms": [],
        "weight": 0,
    },
    {
        "id": "gs_tls_fake_only",
        "name": "TLS Fake Only",
        "category": "tcp",
        "label": "recommended",
        "description": "Только фейковые TLS-пакеты (repeats=6, TTL=3), без нарезки данных.",
        "parameters": _p(
            "fake:blob=fake_default_tls:repeats=6:ip_ttl=3:ip6_ttl=3:tls_mod=rnd,dupsid,sni=www.google.com"
        ),
        "symptoms": ["tls_reset", "just_block"],
        "weight": 10,
    },
    {
        "id": "gs_tls_fake_only_ttl2",
        "name": "TLS Fake Only TTL=2",
        "category": "tcp",
        "label": "recommended",
        "description": "Фейки с TTL=2 и 8 повторами — для плотной фильтрации по SNI.",
        "parameters": _p(
            "fake:blob=fake_default_tls:repeats=8:ip_ttl=2:ip6_ttl=2:tls_mod=rnd,dupsid,sni=www.google.com"
        ),
        "symptoms": ["tls_reset"],
        "weight": 9,
    },
    {
        "id": "gs_tls_fake_only_badseq",
        "name": "TLS Fake Only + BadSeq",
        "category": "tcp",
        "label": "recommended",
        "description": "Фейки с рассинхронизацией последовательности (tcp_ack=-66000).",
        "parameters": _p(
            "fake:blob=fake_default_tls:repeats=6:tcp_ack=-66000:tls_mod=rnd,dupsid,sni=www.google.com"
        ),
        "symptoms": ["tls_reset", "tcp_reset"],
        "weight": 8,
    },
    {
        "id": "gs_tls_fake_only_md5",
        "name": "TLS Fake Only + MD5sig",
        "category": "tcp",
        "label": "recommended",
        "description": "Фейки с md5-подписью TCP — против фильтрации по содержимому.",
        "parameters": _p(
            "fake:blob=fake_default_tls:repeats=6:tcp_md5:tls_mod=rnd,dupsid,sni=www.google.com"
        ),
        "symptoms": ["tls_mitm"],
        "weight": 7,
    },
    {
        "id": "gs_tls_multisplit_sni",
        "name": "TLS MultiSplit SNI",
        "category": "tcp",
        "label": "recommended",
        "description": "Экстремальная нарезка вокруг SNI (17 позиций) с перекрытием 211.",
        "parameters": _p("tls_multisplit_sni:seqovl=211"),
        "symptoms": ["tls_reset", "tcp_16_20"],
        "weight": 10,
    },
    {
        "id": "gs_tls_multisplit_sni_652",
        "name": "TLS MultiSplit SNI seqovl 652",
        "category": "tcp",
        "label": "stable",
        "description": "Нарезка вокруг SNI с перекрытием 652 (паттерн Google TLS).",
        "parameters": _p("tls_multisplit_sni:seqovl=652:seqovl_pattern=tls_google"),
        "symptoms": ["tls_reset", "tcp_16_20"],
        "weight": 9,
    },
    {
        "id": "gs_tls_multisplit_sni_syndata",
        "name": "TLS MultiSplit SNI + syndata",
        "category": "tcp",
        "label": "stable",
        "description": "Нарезка SNI + предпосылка syndata (Google TLS) + seqovl 652.",
        "parameters": _p(
            "send:repeats=2",
            "syndata:blob=tls_google",
            "tls_multisplit_sni:seqovl=652:seqovl_pattern=tls_google",
        ),
        "symptoms": ["tcp_16_20"],
        "weight": 8,
    },
    {
        "id": "gs_hostfakesplit_multi",
        "name": "HostFakeSplit Multi",
        "category": "tcp",
        "label": "stable",
        "description": "Подмена Host в HTTP/SNI на легитимные (google.com, vimeo.com), 2 повтора.",
        "parameters": _p(
            "hostfakesplit_multi:hosts=google.com,vimeo.com:tcp_ts=-1000:tcp_md5:repeats=2"
        ),
        "symptoms": ["tcp_reset", "http_inject", "just_block"],
        "weight": 10,
    },
    {
        "id": "gs_hostfakesplit_multi_syndata",
        "name": "HostFakeSplit Multi + syndata",
        "category": "tcp",
        "label": "stable",
        "description": "HostFakeSplit + первичный пакет syndata со stun_pat.",
        "parameters": _p(
            "send:repeats=2",
            "syndata:blob=stun_pat",
            "hostfakesplit_multi:hosts=google.com,vimeo.com:tcp_ts=-1000:tcp_md5:repeats=2",
        ),
        "symptoms": ["tcp_reset", "http_inject"],
        "weight": 9,
    },
    # ── TCP: фрагментация / нарезка (fakemultisplit, multidisorder) ──────
    {
        "id": "gs_fakemultisplit_simple",
        "name": "FakeMultiSplit Simple",
        "category": "tcp",
        "label": "stable",
        "description": "Базовый fakemultisplit: один разрез (pos=1) + фейк serial TLS.",
        "parameters": _p("fakemultisplit:fake_blob=fake_default_tls:pos=1"),
        "symptoms": ["tls_reset", "tcp_16_20"],
        "weight": 6,
    },
    {
        "id": "gs_fakemultisplit_midsld",
        "name": "FakeMultiSplit MidSLD",
        "category": "tcp",
        "label": "stable",
        "description": "Два разреза: в начале и по середине второго уровня домена.",
        "parameters": _p("fakemultisplit:fake_blob=fake_default_tls:pos=1,midsld"),
        "symptoms": ["tls_reset", "tcp_reset"],
        "weight": 6,
    },
    {
        "id": "gs_fakemultisplit_google_seqovl_211",
        "name": "FakeMultiSplit Google seqovl 211",
        "category": "tcp",
        "label": "stable",
        "description": "Фейковый Google TLS + перекрытие последовательности 211.",
        "parameters": _p(
            "fakemultisplit:fake_blob=tls_google:pos=1,midsld:seqovl=211:seqovl_pattern=tls_google"
        ),
        "symptoms": ["tcp_16_20"],
        "weight": 8,
    },
    {
        "id": "gs_fakemultisplit_google_ultra",
        "name": "FakeMultiSplit Google Ultra",
        "category": "tcp",
        "label": "experimental",
        "description": "Многоточечная нарезка, badseq, перекрытие 652, модификация TLS.",
        "parameters": _p(
            "fakemultisplit:fake_blob=tls_google:pos=1,host+2,midsld,sniext+1,endhost-1:repeats=6:"
            "tcp_ack=-66000:seqovl=652:seqovl_pattern=tls_google:tls_mod=rnd,rndsni,dupsid"
        ),
        "symptoms": ["tcp_16_20"],
        "weight": 7,
    },
    {
        "id": "gs_fakemultidisorder_simple",
        "name": "FakeMultiDisorder Simple",
        "category": "tcp",
        "label": "stable",
        "description": "Сначала фейковый сегмент, затем обратная отправка реальных частей.",
        "parameters": _p("fakemultidisorder:fake_blob=fake_default_tls:pos=1"),
        "symptoms": ["tcp_16_20"],
        "weight": 5,
    },
    {
        "id": "gs_fakemultidisorder_google_ultra",
        "name": "FakeMultiDisorder Google Ultra",
        "category": "tcp",
        "label": "experimental",
        "description": "Фейки всех частей + badseq + AutoTTL, реальные сегменты в disorder-порядке.",
        "parameters": _p(
            "fakemultidisorder:fake_blob=tls_google:pos=1,host+2,midsld,sniext+1,endhost-1:fake_all:"
            "repeats=6:tcp_ack=-66000:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:seqovl=host:"
            "seqovl_pattern=tls_google:tls_mod=rnd,rndsni,dupsid"
        ),
        "symptoms": ["tcp_16_20"],
        "weight": 6,
    },
    # ── TCP: multisplit по позиции + seqovl (обрывы 16-20 КБ) ─────────────
    {
        "id": "gs_multisplit_complex",
        "name": "MultiSplit Complex",
        "category": "tcp",
        "label": "stable",
        "description": "Нарезка по всем ключевым точкам ClientHello с перекрытием 1.",
        "parameters": _p(
            "multisplit:pos=1,host+2,sld+2,sld+5,sniext+1,sniext+2,endhost-2:seqovl=1"
        ),
        "symptoms": ["tcp_reset", "just_block"],
        "weight": 7,
    },
    {
        "id": "gs_multidisorder_complex",
        "name": "MultiDisorder Complex",
        "category": "tcp",
        "label": "stable",
        "description": "MultiDisorder по полному набору позиций с перекрытием 1.",
        "parameters": _p(
            "multidisorder:pos=1,host+2,sld+2,sld+5,sniext+1,sniext+2,endhost-2:seqovl=1"
        ),
        "symptoms": ["tcp_16_20"],
        "weight": 6,
    },
    {
        "id": "gs_multisplit_seqovl_211",
        "name": "MultiSplit seqovl 211",
        "category": "tcp",
        "label": "stable",
        "description": "Разрез на pos=2 с перекрытием 211 (паттерн tls5).",
        "parameters": _p("multisplit:pos=2:seqovl=211:seqovl_pattern=tls5"),
        "symptoms": ["tcp_16_20"],
        "weight": 10,
    },
    {
        "id": "gs_multisplit_seqovl_625",
        "name": "MultiSplit seqovl 625",
        "category": "tcp",
        "label": "stable",
        "description": "Разрез на pos=10 с перекрытием 625 (паттерн tls5).",
        "parameters": _p("multisplit:pos=10:seqovl=625:seqovl_pattern=tls5"),
        "symptoms": ["tcp_16_20"],
        "weight": 9,
    },
    {
        "id": "gs_multisplit_seqovl_700",
        "name": "MultiSplit seqovl 700 (Google)",
        "category": "tcp",
        "label": "experimental",
        "description": "Разрез с перекрытием 700 и паттерном Google TLS.",
        "parameters": _p("multisplit:seqovl=700:seqovl_pattern=tls_google"),
        "symptoms": ["tcp_16_20"],
        "weight": 8,
    },
    {
        "id": "gs_multisplit_seqovl_1000",
        "name": "MultiSplit seqovl 1000 (Google)",
        "category": "tcp",
        "label": "experimental",
        "description": "Разрез с перекрытием 1000 и паттерном Google TLS.",
        "parameters": _p("multisplit:seqovl=1000:seqovl_pattern=tls_google"),
        "symptoms": ["tcp_16_20"],
        "weight": 8,
    },
    {
        "id": "gs_fake_google_tls_badseq",
        "name": "Fake Google TLS + BadSeq",
        "category": "tcp",
        "label": "recommended",
        "description": "Фейк Google TLS с AutoTTL и рассинхронизацией -66000 (6 повторов).",
        "parameters": _p(
            "fake:blob=tls_google:ip_autottl=2,3-20:ip6_autottl=2,3-20:repeats=6:tcp_ack=-66000"
        ),
        "symptoms": ["tls_reset", "tcp_reset", "http_inject"],
        "weight": 9,
    },
    {
        "id": "gs_fake_md5sig_fake_tls",
        "name": "Launcher zapret (md5sig)",
        "category": "tcp",
        "label": "stable",
        "description": "Десинхронизация md5sig с фейком TLS (rnd, rndsni, padencap).",
        "parameters": _p("fake:blob=fake_default_tls:tcp_md5:tls_mod=rnd,rndsni,padencap"),
        "symptoms": ["tls_mitm"],
        "weight": 6,
    },
    {
        "id": "gs_fake_badseq_rnd",
        "name": "YTDisBystro (badseq rnd)",
        "category": "tcp",
        "label": "stable",
        "description": "Фейк tls7 с badseq, подъёмом timestamp и модификацией rnd.",
        "parameters": _p("fake:blob=tls7:tcp_ack=-66000:tcp_ts_up:tls_mod=rnd"),
        "symptoms": ["tls_reset", "tcp_reset"],
        "weight": 7,
    },
    {
        "id": "gs_general_bf_2",
        "name": "general (BF) 2.0",
        "category": "tcp",
        "label": "game",
        "description": "Фейк fake_default_tls с badseq (-66000) и tcp_ts_up — 6 повторов.",
        "parameters": _p("fake:blob=fake_default_tls:repeats=6:tcp_ack=-66000:tcp_ts_up"),
        "symptoms": ["tls_reset", "just_block", "tcp_reset"],
        "weight": 7,
    },
    {
        "id": "gs_fakeddisorder_autottl",
        "name": "FakedDisorder AutoTTL",
        "category": "tcp",
        "label": "stable",
        "description": "FakedDisorder по mid-SLD c AutoTTL и перекрытием 1.",
        "parameters": _p(
            "fakeddisorder:pos=2,midsld-2:pattern=tls7:seqovl=1:tcp_ack=-66000:"
            "ip_autottl=0,3-20:ip6_autottl=0,3-20"
        ),
        "symptoms": ["tcp_16_20"],
        "weight": 6,
    },
    {
        "id": "gs_fakedsplit_badseq",
        "name": "FakedSplit badseq",
        "category": "tcp",
        "label": "recommended",
        "description": "FakedSplit pos=1 c badseq и 10 повторами (TTL 4) — нарезка чанков.",
        "parameters": _p("fakedsplit:pos=1:tcp_ack=-66000:repeats=10:ip_ttl=4:ip6_ttl=4"),
        "symptoms": ["tcp_16_20"],
        "weight": 7,
    },
    {
        "id": "gs_rst_stun_multisplit",
        "name": "STUN + MultiSplit 2,32",
        "category": "tcp",
        "label": "stable",
        "description": "Fake stun_pat с badsum + нарезка по позициям 2 и 32.",
        "parameters": _p(
            "fake:blob=stun_pat:badsum:payload=all",
            "multisplit:pos=2,32:payload=all",
        ),
        "symptoms": ["http_inject"],
        "weight": 5,
    },
    # ── UDP/QUIC: фейковые QUIC-пакеты ──────────────────────────────────
    {
        "id": "gs_fake_quic_x10_autottl",
        "name": "Fake QUIC Google x10 AutoTTL",
        "category": "udp",
        "label": "stable",
        "description": "10 фейков quic_google с авто TTL и payload=all.",
        "parameters": _p(
            "fake:blob=quic_google:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:repeats=10:payload=all"
        ),
        "symptoms": ["quic_drop"],
        "weight": 10,
    },
    {
        "id": "gs_fake_quic_google_x6",
        "name": "Fake QUIC Google x6",
        "category": "udp",
        "label": "recommended",
        "description": "6 фейков quic_google с payload=all.",
        "parameters": _p("fake:blob=quic_google:repeats=6:payload=all"),
        "symptoms": ["quic_drop"],
        "weight": 9,
    },
    {
        "id": "gs_fake_quic_google_x8",
        "name": "Fake QUIC Google x8",
        "category": "voice",
        "label": "recommended",
        "description": "Стандартная стратегия Discord Voice: 8 фейков Google QUIC.",
        "parameters": _p("fake:blob=quic_google:repeats=8"),
        "symptoms": ["quic_drop", "stun_block"],
        "weight": 9,
    },
    {
        "id": "gs_fake_quic_google_x11",
        "name": "Fake QUIC Google x11",
        "category": "udp",
        "label": "stable",
        "description": "11 фейков Google QUIC — при выраженных обрывах UDP.",
        "parameters": _p("fake:blob=quic_google:repeats=11"),
        "symptoms": ["quic_drop"],
        "weight": 8,
    },
    {
        "id": "gs_fake_quic_google_x12",
        "name": "Fake QUIC Google x12",
        "category": "udp",
        "label": "stable",
        "description": "12 фейков Google QUIC (агрессивно).",
        "parameters": _p("fake:blob=quic_google:repeats=12"),
        "symptoms": ["quic_drop"],
        "weight": 8,
    },
    {
        "id": "gs_fake_quic_amazon",
        "name": "Fake QUIC Amazon (Preset.X1)",
        "category": "udp",
        "label": "stable",
        "description": "10 фейков Google QUIC с авто TTL и payload=all (Amazon UDP).",
        "parameters": _p(
            "fake:blob=quic_google:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:payload=all:repeats=10"
        ),
        "symptoms": ["quic_drop"],
        "weight": 7,
    },
    {
        "id": "gs_fake_quic6_ttl7",
        "name": "Fake QUIC6 TTL7",
        "category": "udp",
        "label": "game",
        "description": "2 фейка quic6 с TTL 7 и payload=all.",
        "parameters": _p("fake:blob=quic6:repeats=2:ip_ttl=7:ip6_ttl=7:payload=all"),
        "symptoms": ["quic_drop"],
        "weight": 6,
    },
    {
        "id": "gs_general_bf_32",
        "name": "General-BF 3.2 (game)",
        "category": "udp",
        "label": "game",
        "description": "9 фейков Google QUIC с авто TTL и payload=all — для игр.",
        "parameters": _p(
            "fake:blob=quic_google:repeats=9:ip_autottl=2,3-20:ip6_autottl=2,3-20:payload=all"
        ),
        "symptoms": ["quic_drop"],
        "weight": 7,
    },
    {
        "id": "gs_rockstar",
        "name": "Rockstar v3",
        "category": "udp",
        "label": "game",
        "description": "2 фейка quic_test с payload=all (R*, Apex).",
        "parameters": _p("fake:blob=quic_test:repeats=2:payload=all"),
        "symptoms": ["quic_drop"],
        "weight": 5,
    },
    {
        "id": "gs_fake_quic6_autottl_udplen",
        "name": "Fake QUIC6 AutoTTL + UDPLen",
        "category": "udp",
        "label": "stable",
        "description": "Fake quic6 с авто TTL + увеличение длины UDP на 8 (паттерн 0x0F0F0E0F).",
        "parameters": _p(
            "fake:blob=quic6:repeats=2:ip_autottl=-1,3-20:ip6_autottl=-1,3-20:payload=all",
            "udplen:increment=8:pattern=0x0F0F0E0F",
        ),
        "symptoms": ["quic_drop"],
        "weight": 6,
    },
    {
        "id": "gs_fake_udplen_25_x10",
        "name": "Fake+UDPLen+25 x10",
        "category": "udp",
        "label": "stable",
        "description": "10 фейков Google QUIC с изменением длины UDP на +25.",
        "parameters": _p(
            "fake:blob=quic_google:repeats=10",
            "udplen:increment=25",
        ),
        "symptoms": ["quic_drop"],
        "weight": 5,
    },
    {
        "id": "gs_fake_tamper_dht",
        "name": "Fake+Tamper DHT",
        "category": "udp",
        "label": "recommended",
        "description": "11 фейков Google QUIC + tamper (DHT) — обходит блокировку UDP-торрентов.",
        "parameters": _p("fake:blob=quic_google:repeats=11", "dht_dn:dn=2"),
        "symptoms": ["quic_drop"],
        "weight": 5,
    },
    # ── UDP/STUN: голосовые и STUN-блокировки ────────────────────────────
    {
        "id": "gs_fake_stun_0x00",
        "name": "Fake STUN+Discord 0x00",
        "category": "voice",
        "label": "stable",
        "description": "Один нулевой пакет для STUN и Discord IP Discovery.",
        "parameters": _p("fake:blob=0x00"),
        "symptoms": ["stun_block"],
        "weight": 8,
    },
    {
        "id": "gs_fake_stun_x6",
        "name": "Fake STUN+Discord x6",
        "category": "voice",
        "label": "recommended",
        "description": "6 нулевых пакетов для STUN и Discord IP Discovery.",
        "parameters": _p("fake:blob=0x00:repeats=6"),
        "symptoms": ["stun_block"],
        "weight": 9,
    },
    {
        "id": "gs_fake_stun_16bytes",
        "name": "Fake STUN+Discord 16 bytes",
        "category": "voice",
        "label": "recommended",
        "description": "2 нулевых пакета по 16 байт для STUN и Discord.",
        "parameters": _p("fake:blob=0x00000000000000000000000000000000:repeats=2"),
        "symptoms": ["stun_block"],
        "weight": 8,
    },
    {
        "id": "gs_fake_stun_autottl",
        "name": "Fake STUN+Discord AutoTTL",
        "category": "voice",
        "label": "recommended",
        "description": "4 нулевых пакета с авто TTL для STUN и Discord IP Discovery.",
        "parameters": _p("fake:blob=0x00:repeats=4:ip_autottl=0,3-20:ip6_autottl=0,3-20"),
        "symptoms": ["stun_block"],
        "weight": 7,
    },
    {
        "id": "gs_fake_stun_pat_x6",
        "name": "Fake STUN-pat x6",
        "category": "udp",
        "label": "stable",
        "description": "6 повторов stun_pat — для голосовых поверх UDP.",
        "parameters": _p("fake:blob=stun_pat:repeats=6"),
        "symptoms": ["stun_block"],
        "weight": 6,
    },
    {
        "id": "gs_voice_google_x8",
        "name": "fake 8 google (Voice)",
        "category": "voice",
        "label": "recommended",
        "description": "Стандарт Discord Voice: 8 повторов Google QUIC.",
        "parameters": _p("fake:blob=quic_google:repeats=8"),
        "symptoms": ["stun_block", "quic_drop"],
        "weight": 10,
    },
    {
        "id": "gs_voice_vk_x6",
        "name": "fake 6 quic vk.com (Voice)",
        "category": "voice",
        "label": "recommended",
        "description": "6 повторов QUIC от VK — стандарт Discord Voice.",
        "parameters": _p("fake:blob=quic_vk:repeats=6"),
        "symptoms": ["stun_block"],
        "weight": 5,
    },
    {
        "id": "gs_voice_ufanet",
        "name": "Ufanet 31.03.2025",
        "category": "voice",
        "label": "recommended",
        "description": "6 повторов Google QUIC + UDPLen+10 (0xDEADBEEF) для Discord Voice.",
        "parameters": _p(
            "fake:blob=quic_google:repeats=6",
            "udplen:increment=10:pattern=0xDEADBEEF",
        ),
        "symptoms": ["stun_block", "quic_drop"],
        "weight": 6,
    },
    {
        "id": "gs_voice_ytdis",
        "name": "YTDis Bystro (Voice)",
        "category": "voice",
        "label": "recommended",
        "description": "7 повторов quic2 + UDPLen+5 (0xDEADBEEF).",
        "parameters": _p(
            "fake:blob=quic2:repeats=7",
            "udplen:increment=5:pattern=0xDEADBEEF",
        ),
        "symptoms": ["stun_block"],
        "weight": 5,
    },
]


def _by_id() -> Dict[str, Dict[str, Any]]:
    return {strategy["id"]: strategy for strategy in STRATEGIES}


# Симптом → список id стратегий (в порядке предпочтения).
SYMPTOM_TO_STRATEGY: Dict[str, List[str]] = {
    "dns_poisoning": ["gs_pass"],
    "tls_reset": [
        "gs_tls_fake_only",
        "gs_tls_multisplit_sni",
        "gs_fake_google_tls_badseq",
        "gs_tls_fake_only_ttl2",
        "gs_hostfakesplit_multi",
        "gs_tls_fake_only_badseq",
        "gs_fakemultisplit_simple",
        "gs_fake_badseq_rnd",
        "gs_general_bf_2",
    ],
    "tls_mitm": [
        "gs_tls_fake_only_md5",
        "gs_fake_md5sig_fake_tls",
        "gs_tls_fake_only_badseq",
        "gs_hostfakesplit_multi",
    ],
    "http_inject": [
        "gs_hostfakesplit_multi",
        "gs_fake_google_tls_badseq",
        "gs_multisplit_complex",
        "gs_hostfakesplit_multi_syndata",
        "gs_fakemultisplit_midsld",
        "gs_rst_stun_multisplit",
    ],
    "isp_page": [
        "gs_hostfakesplit_multi",
        "gs_fake_google_tls_badseq",
        "gs_multisplit_complex",
        "gs_fakemultisplit_midsld",
    ],
    "tcp_reset": [
        "gs_hostfakesplit_multi",
        "gs_hostfakesplit_multi_syndata",
        "gs_fake_google_tls_badseq",
        "gs_fake_badseq_rnd",
        "gs_multisplit_complex",
        "gs_fakemultisplit_midsld",
        "gs_general_bf_2",
        "gs_tls_fake_only_badseq",
    ],
    "tcp_16_20": [
        "gs_multisplit_seqovl_211",
        "gs_tls_multisplit_sni",
        "gs_multisplit_seqovl_625",
        "gs_fakemultisplit_google_seqovl_211",
        "gs_fakedsplit_badseq",
        "gs_multisplit_seqovl_700",
        "gs_multisplit_seqovl_1000",
        "gs_tls_multisplit_sni_652",
        "gs_tls_multisplit_sni_syndata",
        "gs_fakemultisplit_google_ultra",
        "gs_fakeddisorder_autottl",
        "gs_multidisorder_complex",
    ],
    "stun_block": [
        "gs_voice_google_x8",
        "gs_fake_stun_x6",
        "gs_fake_stun_0x00",
        "gs_fake_stun_16bytes",
        "gs_fake_stun_autottl",
        "gs_fake_stun_pat_x6",
        "gs_voice_vk_x6",
        "gs_voice_ufanet",
        "gs_voice_ytdis",
        "gs_fake_quic_google_x8",
    ],
    "quic_drop": [
        "gs_fake_quic_x10_autottl",
        "gs_fake_quic_google_x6",
        "gs_fake_quic_google_x8",
        "gs_fake_quic_google_x11",
        "gs_fake_quic_google_x12",
        "gs_fake_quic_amazon",
        "gs_general_bf_32",
        "gs_fake_quic6_ttl7",
        "gs_fake_quic6_autottl_udplen",
        "gs_fake_udplen_25_x10",
        "gs_fake_tamper_dht",
        "gs_rockstar",
    ],
    "full_block": [],
    "just_block": [
        "gs_tls_fake_only",
        "gs_hostfakesplit_multi",
        "gs_multisplit_complex",
        "gs_general_bf_2",
    ],
}


def _summary(strategy: Dict[str, Any]) -> Dict[str, Any]:
    key_params: List[str] = []
    for key, values in (strategy.get("parameters") or {}).get("add", {}).items():
        if key == "--lua-desync":
            if isinstance(values, str):
                key_params.append(values)
            else:
                key_params.extend(values)
    return {
        "id": strategy["id"],
        "strategy": strategy["id"],
        "name": strategy["name"],
        "category": strategy["category"],
        "label": strategy["label"],
        "description": strategy["description"],
        "symptoms": list(strategy.get("symptoms") or []),
        "key_parameters": key_params[:3],
    }


def available_strategies() -> List[Dict[str, Any]]:
    return [_summary(strategy) for strategy in STRATEGIES]


def find_strategy_by_id(strategy_id: str) -> Optional[Dict[str, Any]]:
    strategy = _by_id().get(strategy_id)
    return dict(strategy) if strategy else None


def create_strategy_for_failure_type(failure_type: str) -> Optional[Dict[str, Any]]:
    """Возвращает рекомендованную стратегию (summary) для типа сбоя."""
    symptom = FAILURE_TO_SYMPTOM.get(failure_type or "")
    if not symptom:
        return None
    candidates = SYMPTOM_TO_STRATEGY.get(symptom, [])
    if not candidates:
        return None
    strategy = _by_id().get(candidates[0])
    return _summary(strategy) if strategy else None


def rank_recommendations(
    symptoms: List[str],
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Топ-N стратегий по набору симптомов.

    Каждая запись: ``{strategy, id, name, probability, matched_symptoms,
    description, category, label}``. Стратегия повторяет себя в нескольких
    списках симптомов — вероятность растёт с числом совпадений.
    """
    by_id = _by_id()
    scored: Dict[str, Dict[str, Any]] = {}

    for symptom in symptoms:
        for strategy_id in SYMPTOM_TO_STRATEGY.get(symptom, []):
            if strategy_id not in by_id:
                continue
            entry = scored.setdefault(
                strategy_id,
                {
                    "strategy": strategy_id,
                    "id": strategy_id,
                    "name": by_id[strategy_id]["name"],
                    "category": by_id[strategy_id]["category"],
                    "label": by_id[strategy_id]["label"],
                    "description": by_id[strategy_id]["description"],
                    "probability": 0.0,
                    "matched_symptoms": [],
                },
            )
            entry["matched_symptoms"].append(
                {
                    "symptom": symptom,
                    "approach": SYMPTOMS.get(symptom, {}).get("approach", ""),
                }
            )

    ordered = sorted(
        scored.values(),
        key=lambda entry: (
            -round(min(0.95, 0.60 + 0.15 * (len(entry["matched_symptoms"]) - 1)), 2),
            -by_id[entry["id"]].get("weight", 0),
        ),
    )
    for entry in ordered[:limit]:
        entry["probability"] = round(
            min(0.95, 0.60 + 0.15 * (len(entry["matched_symptoms"]) - 1)), 2
        )
    return ordered[:limit]