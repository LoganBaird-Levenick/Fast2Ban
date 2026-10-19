// Generated from upstream strptime.timeRE (Python 3.14.4, C locale, PYTHONHASHSEED=0).
// Dict order of `timeRE` is preserved. `ExY` is a placeholder: it is computed from the year window.

/// `(key, regex)` of upstream `strptime.timeRE`.
pub(crate) const TIME_RE: &[(&str, &str)] = &[
    (r"d", r"(?P<d>[1-2]\d|[0 ]?[1-9]|3[0-1])"),
    (r"f", r"(?P<f>[0-9]{1,6})"),
    (r"H", r"(?P<H>[0-1]?\d|2[0-3])"),
    (r"k", r" ?(?P<H>[0-2]?\d)"),
    (r"I", r"(?P<I>1[0-2]|0[1-9]|[1-9]| [1-9])"),
    (r"l", r" ?(?P<I>1?\d)"),
    (r"G", r"(?P<G>\d\d\d\d)"),
    (
        r"j",
        r"(?P<j>36[0-6]|3[0-5]\d|[1-2]\d\d|0[1-9]\d|00[1-9]|[1-9]\d|0[1-9]|[1-9])",
    ),
    (r"m", r"(?P<m>0?[1-9]|1[0-2])"),
    (r"M", r"(?P<M>[0-5]?\d)"),
    (r"S", r"(?P<S>[0-5]?\d|6[0-1])"),
    (r"U", r"(?P<U>5[0-3]|[0-4]\d|\d)"),
    (r"w", r"(?P<w>[0-6])"),
    (r"u", r"(?P<u>[1-7])"),
    (r"V", r"(?P<V>5[0-3]|0[1-9]|[1-4]\d|\d)"),
    (r"y", r"(?P<y>\d\d)"),
    (r"Y", r"(?P<Y>\d{4})"),
    (r"z", r"(?P<z>Z|UTC|GMT|[+-][01]\d(?::?\d{2})?)"),
    (
        r"A",
        r"(?P<A>wednesday|thursday|saturday|tuesday|monday|friday|sunday)",
    ),
    (r"a", r"(?P<a>mon|tue|wed|thu|fri|sat|sun)"),
    (
        r"B",
        r"(?P<B>september|february|november|december|january|october|august|march|april|june|july|may)",
    ),
    (
        r"b",
        r"(?P<b>jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)",
    ),
    (r"p", r"(?P<p>am|pm)"),
    (r"Z", r"(?P<Z>Z|[A-Z]{3,5})"),
    (r"%", r"%"),
    (r"Od", r""),
    (r"Om", r""),
    (r"Ow", r""),
    (r"Oy", r""),
    (r"OC", r""),
    (r"OH", r""),
    (r"OI", r""),
    (r"OM", r""),
    (r"OS", r""),
    (r"e", r"(?P<d>3[0-1]|[1-2]\d|0[1-9]|[1-9]| [1-9])"),
    (r"Oe", r""),
    (r"P", r"(?P<p>am|pm)"),
    (r"Op", r"(?P<p>am|pm)"),
    (r"W", r"(?P<W>5[0-3]|[0-4]\d|\d)"),
    (
        r"T",
        r"(?P<H>2[0-3]|[0-1]\d|\d| \d):(?P<M>[0-5]\d|\d):(?P<S>6[0-1]|[0-5]\d|\d)",
    ),
    (r"R", r"(?P<H>2[0-3]|[0-1]\d|\d| \d):(?P<M>[0-5]\d|\d)"),
    (
        r"r",
        r"(?P<I>1[0-2]|0[1-9]|[1-9]| [1-9]):(?P<M>[0-5]\d|\d):(?P<S>6[0-1]|[0-5]\d|\d)\s+(?P<p>am|pm)",
    ),
    (
        r"X",
        r"(?P<H>2[0-3]|[0-1]\d|\d| \d):(?P<M>[0-5]\d|\d):(?P<S>6[0-1]|[0-5]\d|\d)",
    ),
    (
        r"x",
        r"(?P<m>1[0-2]|0[1-9]|[1-9])/(?P<d>3[0-1]|[1-2]\d|0[1-9]|[1-9]| [1-9])/(?P<y>\d\d)",
    ),
    (
        r"c",
        r"(?P<a>mon|tue|wed|thu|fri|sat|sun)\s+(?P<b>jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+(?P<d>3[0-1]|[1-2]\d|0[1-9]|[1-9]| [1-9])\s+(?P<H>2[0-3]|[0-1]\d|\d| \d):(?P<M>[0-5]\d|\d):(?P<S>6[0-1]|[0-5]\d|\d)\s+(?P<Y>\d\d\d\d)",
    ),
    (r"ExZ", r"(?P<Z>[A-Z](?:[A-Z]{2,4})?)"),
    (
        r"Exz",
        r"(?P<z>(?:[A-Z](?:[A-Z]{2,4})?)?[+-][01]\d(?::?\d{2})?|[A-Z](?:[A-Z]{2,4})?)",
    ),
    (r"Exd", r"(?P<d>[1-2]\d|0[1-9]|3[0-1])"),
    (r"Exm", r"(?P<m>0[1-9]|1[0-2])"),
    (r"ExH", r"(?P<H>[0-1]\d|2[0-3])"),
    (r"Exk", r" ?(?P<H>[0-1]?\d|2[0-3])"),
    (r"Exl", r" ?(?P<I>1[0-2]|\d)"),
    (r"ExM", r"(?P<M>[0-5]\d)"),
    (r"ExS", r"(?P<S>[0-5]\d|6[0-1])"),
    (r"ExY", r"@EXY@"),
    (r"Exy", r"(?P<y>\d{2})"),
];

/// `(key, display name)` of upstream `getTimePatternRE()[1]` (hash seed 0).
pub(crate) const TIME_NAMES: &[(&str, &str)] = &[
    (r"d", r"Day"),
    (r"f", r"Microseconds"),
    (r"H", r"24hour"),
    (r"k", r"%k"),
    (r"I", r"12hour"),
    (r"l", r"%l"),
    (r"G", r"%G"),
    (r"j", r"Yearday"),
    (r"m", r"Month"),
    (r"M", r"Minute"),
    (r"S", r"Second"),
    (r"U", r"Yearweek"),
    (r"w", r"Weekday"),
    (r"u", r"%u"),
    (r"V", r"%V"),
    (r"y", r"Year2"),
    (r"Y", r"Year"),
    (r"z", r"Zone offset"),
    (r"A", r"DAYNAME"),
    (r"a", r"DAY"),
    (r"B", r"MONTH"),
    (r"b", r"MON"),
    (r"p", r"AMPM"),
    (r"Z", r"Zone name"),
    (r"%", r"%"),
    (r"Od", r"%Od"),
    (r"Om", r"%Om"),
    (r"Ow", r"%Ow"),
    (r"Oy", r"%Oy"),
    (r"OC", r"%OC"),
    (r"OH", r"%OH"),
    (r"OI", r"%OI"),
    (r"OM", r"%OM"),
    (r"OS", r"%OS"),
    (r"e", r"%e"),
    (r"Oe", r"%Oe"),
    (r"P", r"%P"),
    (r"Op", r"%Op"),
    (r"W", r"Yearweek"),
    (r"T", r"%T"),
    (r"R", r"%R"),
    (r"r", r"%r"),
    (r"X", r"%X"),
    (r"x", r"%x"),
    (r"c", r"%c"),
    (r"ExZ", r"ExZone name"),
    (r"Exz", r"ExZone offset"),
    (r"Exd", r"ExDay"),
    (r"Exm", r"ExMonth"),
    (r"ExH", r"Ex24hour"),
    (r"Exk", r"%Exk"),
    (r"Exl", r"%Exl"),
    (r"ExM", r"ExMinute"),
    (r"ExS", r"ExSecond"),
    (r"ExY", r"ExYear"),
    (r"Exy", r"ExYear2"),
];

/// Upstream `TZ_STR`.
pub(crate) const TZ_STR: &str = r"
	-12 Y
	-11 X NUT SST
	-10 W CKT HAST HST TAHT TKT
	-9 V AKST GAMT GIT HADT HNY
	-8 U AKDT CIST HAY HNP PST PT
	-7 T HAP HNR MST PDT
	-6 S CST EAST GALT HAR HNC MDT
	-5 R CDT COT EASST ECT EST ET HAC HNE PET
	-4 Q AST BOT CLT COST EDT FKT GYT HAE HNA PYT
	-3 P ADT ART BRT CLST FKST GFT HAA PMST PYST SRT UYT WGT
	-2 O BRST FNT PMDT UYST WGST
	-1 N AZOT CVT EGT
	0 Z EGST GMT UTC WET WT
	1 A CET DFT WAT WEDT WEST
	2 B CAT CEDT CEST EET SAST WAST
	3 C EAT EEDT EEST IDT MSK
	4 D AMT AZT GET GST KUYT MSD MUT RET SAMT SCT
	5 E AMST AQTT AZST HMT MAWT MVT PKT TFT TJT TMT UZT YEKT
	6 F ALMT BIOT BTT IOT KGT NOVT OMST YEKST
	7 G CXT DAVT HOVT ICT KRAT NOVST OMSST THA WIB
	8 H ACT AWST BDT BNT CAST HKT IRKT KRAST MYT PHT SGT ULAT WITA WST
	9 I AWDT IRKST JST KST PWT TLT WDT WIT YAKT
	10 K AEST ChST PGT VLAT YAKST YAPT
	11 L AEDT LHDT MAGT NCT PONT SBT VLAST VUT
	12 M ANAST ANAT FJT GILT MAGST MHT NZST PETST PETT TVT WFT
	13 FJST NZDT
	11.5 NFT
	10.5 ACDT LHST
	9.5 ACST
	6.5 CCT MMT
	5.75 NPT
	5.5 SLT
	4.5 AFT IRDT
	3.5 IRST
	-2.5 HAT NDT
	-3.5 HNT NST NT
	-4.5 HLV VET
	-9.5 MART MIT
";
