# Binary Waterfall Diff View — mätmodell och tolkningsguide

## Omfattning och nuläge

Detta dokument gäller **Binary Waterfall Diff View**: den tvåsidiga jämförelsen mellan två `BinarySnapshot`-objekt och det vattenfall som avgör vilka difflager som får köras.

Det finns två närliggande delar i implementationen:

- Den vanliga GUI-fliken **Binary Waterfall** visar coverage-ranges, anchors, unknown regions och record families för **ett** snapshot.
- Tjänsten **Binary Snapshot Diff** jämför **två** snapshots och returnerar ett `waterfall`-kontrakt med kompatibilitetsklass, tillåtelse för automatisk diff och segment-alignment.

En fullständig tvåsidig Waterfall Diff-tabell är alltså ett presentationslager över dessa befintliga kontrakt. Den underliggande jämförelselogiken finns, men den nuvarande `Binary Waterfall`-fliken i `src/ui.py` är fortfarande en enkelsnapshot-vy. Dokumentet beskriver både vad den tvåsidiga vyn ska presentera och exakt vad den befintliga tjänsten faktiskt mäter; det påstår inte att en färdig tvåsidig Qt-vy redan är inkopplad.

## Syfte

Binary Waterfall Diff svarar på tre separata frågor:

1. Är snapshotarna strukturellt jämförbara?
2. Har källfilens identitet, parsernoder eller grafrelationer förändrats?
3. Kan resultaten visas med direkta positioner, eller måste strukturellt motsvarande segment först riktas in mot varandra?

Diffen är deterministisk och policy-driven. Formatidentitet, obligatoriska fält och trösklar hämtas från `config/binary_diff_policy.json`; de ligger inte som filnamn, projektspecifika strängar eller kända offsetar i diffkoden.

> **Viktigt:** Den nuvarande tjänsten är en snapshot- och strukturdiff. Den räknar inte fram ändrade byteintervall och gör inte en byte-för-byte-jämförelse av filinnehållet.

## Vad som jämförs

Indata är två snapshots, här kallade **left** och **right**. Ett snapshot innehåller bland annat:

- källans SHA-256 och metadata;
- formatplugin och parser-/registry-identitet;
- coverage-segment med klass, offset och längd;
- parsernoder med stabila ID:n;
- grafkanter med stabila ID:n;
- samlade `signals` från analysen.

Snapshot-ID:n används för spårbarhet i resultatet. De används inte som likhetsmått.

## Waterfall-mätkedjan

Jämförelsen sker som ett vattenfall. Ett senare lager körs bara om kompatibilitetsgrinden tillåter automatisk diff.

```text
vänster och höger BinarySnapshot
        |
        v
identitet och policyfält
        |
        v
sekvenslikhet för coverage-klasser och nodtyper
        |
        +---- inkompatibel ---> raw/parsed/runtime hoppas över
        |
        v
exakt eller strukturell layout
        |
        v
raw-identitet + noddiff + graf/signaldiff
```

## 1. Kompatibilitetsgrinden

### Format och identitetsfält

Först måste båda snapshots ange samma `format_plugin`. Därefter slås standardpolicyn ihop med den aktiva pluginens policy.

Policyn kan ange:

- `required_equal_fields`: fält som måste finnas på båda sidor och vara lika;
- `optional_equal_fields`: fält som får saknas på båda sidor, men måste vara lika om de finns;
- vilket fält som representerar coverage-klass;
- minsta godkända likhet för coverage- och nodsekvenser.

Fältsökvägar kan vara nästlade, till exempel `signals.profile_id`. Därmed kan nya formatvarianter beskrivas i policy i stället för genom projektspecifika villkor i Python-koden.

### Coverage sequence similarity

Varje coverage-post omvandlas till sin klass. Direkt efterföljande dubbletter kollapsas:

```text
header, records, records, unknown
             blir
header, records, unknown
```

Vänster och höger klassföljd jämförs sedan med Python `difflib.SequenceMatcher`, med `autojunk=False`. Resultatet `coverage_sequence_similarity` ligger mellan `0.0` och `1.0`:

- `1.0` betyder att de kollapsade klassföljderna är identiska;
- `0.0` betyder att algoritmen inte hittar någon gemensam sekvens;
- värden däremellan beskriver ordningslikhet enligt `SequenceMatcher.ratio()`.

Detta är ett sekvensmått. Det är inte procent identiska bytes, statistisk konfidens eller parserkorrekthet.

### Node-kind sequence similarity

Samma metod används för nodernas `kind` i den ordning de förekommer i snapshotet. Direkt efterföljande dubbletter kollapsas före mätningen. Resultatet heter `node_kind_sequence_similarity`.

Om någon av likheterna ligger under sin policytröskel klassas paret som inkompatibelt. Om båda sekvenserna är tomma blir likheten `1.0`; om bara en är tom blir den `0.0`.

### Klassificering

Kompatibilitetsgrinden ger en av tre klasser:

| Klass | Faktisk innebörd | Diffbeteende |
|---|---|---|
| `exact` | Identitetsfält matchar, hela listan av `(coverage-klass, offset, längd)` är identisk och den kollapsade nodtypsföljden är identisk. | Direkt snapshot-diff. |
| `structural` | Identitetsfält matchar och sekvensmåtten klarar policyn, men layouten är inte exakt. | Diff körs med strukturell segmentinriktning. |
| `incompatible` | Format/identitet skiljer sig, något kravfält saknas eller skiljer sig, eller ett sekvensmått ligger under tröskeln. | Alla tre automatiska difflager hoppas över. |

`exact` betyder alltså exakt layout enligt ovan. Det betyder inte att filerna har identiska bytes.

## 2. Segmentinriktning

För ett godkänt par riktas coverage-poster in genom att köra `SequenceMatcher` på den fullständiga följden av coverage-klasser. Varje matchande post ger:

- coverage-klassen;
- vänster offset och längd;
- höger offset och längd.

Inriktningen matchar klass och ordning. Den granskar inte bytesen inuti segmentet. Vid `structural` diff gör detta att samma logiska sektion kan kopplas ihop även om dess absoluta offset eller längd har flyttats.

Poster som inte ingår i ett matchande block finns inte i `alignment`. De ska inte tolkas som automatiskt matchade bara för att de råkar ligga nära varandra.

## 3. Raw-lagret

Raw-lagret mäter för närvarande källidentitet:

```text
source_changed = left.source.sha256 != right.source.sha256
```

Det redovisar vänster och höger SHA-256 samt läget:

- `direct` för `exact` kompatibilitet;
- `aligned_segments` för `structural` kompatibilitet.

Det mäter **inte**:

- antal ändrade bytes;
- första eller sista ändrade offset;
- infogningar och borttagningar i råfilen;
- byte-edit distance;
- innehållsskillnader per alignment-segment.

`source_changed: true` betyder endast att de två SHA-256-värdena skiljer sig. `false` betyder att värdena är lika; tilliten till detta beror på att snapshots innehåller korrekta källhashar.

## 4. Parsed-lagret

Parsernoder indexeras efter `id`. Matchningsstrategin rapporteras som `stable_provenance_id`.

Lagret producerar:

- `added_node_ids`: ID:n som bara finns till höger;
- `removed_node_ids`: ID:n som bara finns till vänster;
- `changed_node_ids`: ID:n som finns på båda sidor men vars kompletta serialiserade nodobjekt inte är lika.

En ändrad nod kan alltså bero på exempelvis label, source range, confidence, parser rule, evidence class eller attributes. Resultatet anger ännu inte vilket enskilt nodfält som ändrades.

Stabila ID:n är centrala. Ett logiskt objekt som får ett nytt ID visas som borttaget plus tillagt, inte som ändrat. I den nuvarande snapshotmodellen byggs nod-ID:n normalt deterministiskt från nodtyp, källhash, offset, längd och eventuell RVA. Det innebär att en förändrad källhash eller position kan påverka identitetsmatchningen även när användaren uppfattar posten som samma logiska objekt.

## 5. Runtime-/graflagret

Grafkanter indexeras också efter stabilt `id`. Lagret redovisar:

- `added_edge_ids`;
- `removed_edge_ids`;
- `signals_changed`.

`signals_changed` är en vanlig full objektjämförelse mellan vänster och höger `signals`. Den är sann om något värde, någon nyckel eller någon nästlad struktur skiljer sig. Den visar inte vilket signalfält som ändrades.

Namnet `runtime` i diffkontraktet är historiskt/brett: jämförelsen använder snapshotets `edges` och `signals`. Den gör inte en tidsserieanalys och kör inte filen.

## Resultatkontrakt

Ett godkänt resultat har status `compared` och innehåller huvuddelarna:

```json
{
  "status": "compared",
  "compatibility": {
    "classification": "exact eller structural",
    "automatic_diff_allowed": true,
    "metrics": {
      "coverage_sequence_similarity": 0.0,
      "node_kind_sequence_similarity": 0.0
    }
  },
  "raw": {
    "performed": true,
    "mode": "direct eller aligned_segments",
    "source_changed": true
  },
  "parsed": {
    "performed": true,
    "added_node_ids": [],
    "removed_node_ids": [],
    "changed_node_ids": []
  },
  "runtime": {
    "performed": true,
    "added_edge_ids": [],
    "removed_edge_ids": [],
    "signals_changed": false
  }
}
```

Siffrorna i exemplet är endast kontraktsplatshållare, inte inbyggda trösklar eller förväntade resultat.

Vid inkompatibilitet blir status `incompatible`. `raw`, `parsed` och `runtime` får då `performed: false` och orsaken `structural_compatibility_gate`. Det är avsiktligt: systemet ska inte skapa missvisande automatiska skillnader mellan snapshots som saknar tillräckligt gemensam struktur.

## Binary Waterfall Diff View — presentation

Den tvåsidiga Binary Waterfall Diff-vyn bör visa informationen i denna ordning:

1. **Kompatibilitet:** klass, orsaker, jämförda identitetsfält och sekvensmått.
2. **Raw identity:** om källhashen ändrades och vilket diffläge som användes.
3. **Parsed objects:** antal samt listor över tillagda, borttagna och ändrade nod-ID:n.
4. **Graph/signals:** tillagda/borttagna kanter och om signalobjektet ändrades.
5. **Alignment:** vänster/höger offset och längd för mekaniskt matchade coverage-segment.

Vyn ska märka likhetsvärden som **strukturell sekvenslikhet**, inte som “procent lika bytes”. Den ska även visa `performed: false` som blockerad/ej utförd, inte som “inga skillnader”. Vänster och höger sida ska bindas till sina snapshot-ID:n och källhashar så att offsetkolumnerna aldrig blandas ihop.

Navigering till offset är säker bara för poster som faktiskt har en offset i alignment eller i den valda nodens provenance. Enbart ett nod- eller edge-ID är inte i sig en filposition.

## Skillnad mot enkelsnapshot-vyn och Transform Diff

Den befintliga GUI-fliken **Binary Waterfall** presenterar ett snapshots coverage och relaterad strukturell evidens. Den är datakällan för en sida av jämförelsen, men utför inte själv pardiffen.

Dialogens nuvarande flik **Transform Diff** presenterar transform-scope-evidens och dess ranges. Den är inte samma komponent som tjänsten `binary_snapshot_diff` och ska inte beskrivas som en full råfilsdiff.

- **Binary Waterfall:** visar strukturella ranges för ett snapshot.
- **Binary Waterfall Diff / Binary Snapshot Diff:** jämför två snapshots enligt vattenfallsmodellen i detta dokument.
- **Transform Diff:** visar evidens för förändrade transform-scope-ranges från analysartefakter.

När snapshot-diffen exponeras som GUI-vy ska den därför heta **Binary Waterfall Diff** och inte återanvända Transform Diff-rubriken.

## Vad resultaten inte bevisar

Binary Waterfall Diff bevisar inte att:

- två filer är semantiskt likvärdiga;
- parsningen är korrekt eller komplett;
- en ändring är kryptering, dekryptering eller plaintext;
- en ändrad nod motsvarar exakt ett ändrat record i originalformatet;
- ett matchat coverage-segment har identiskt byteinnehåll;
- en hög sekvenslikhet är statistisk konfidens;
- en modell- eller parserhypotes får promoveras.

Diffen är mekanisk evidens. Den kan peka ut kandidater för fortsatt analys, men promotion och formatpåståenden kräver separata verifieringsgrindar.

## Konfiguration utan hardcode

Den auktoritativa policyn ligger i AI Lab-konfigurationen `config/binary_diff_policy.json`. Där definieras standardfält, pluginfält och likhetströsklar. För att stödja ett nytt format:

1. registrera formatets identitetsfält i policyn;
2. säkerställ att snapshotproducenten emitterar stabila noder, kanter och coverage-klasser;
3. lägg regressionstester för `exact`, `structural` och `incompatible`;
4. undvik filnamn, kända projektoffsetar, hashes och formatspecifika strängar i diffmotorn eller GUI:t.

Policyn innehåller även vikter för coverage och node kind. De läses in som policydata men används inte av den nuvarande kompatibilitetsalgoritmen för att skapa ett sammanvägt totalvärde. Vyn ska därför inte visa något viktat totalscore förrän tjänsten faktiskt producerar ett sådant mått.

## Implementation och verifiering

De centrala implementationerna är:

- `src/ui.py` — nuvarande enkelsnapshot-flik för Binary Waterfall;
- `src/services/binary_runtime.py` — Waterfall-payload och dess comparison contract;
- `src/services/binary_compatibility.py` — policyinläsning, identitetskontroll, sekvensmått, klassificering och alignment;
- `src/services/binary_snapshot_diff.py` — raw-, parsed- och runtime-resultat;
- `src/runtime/snapshot.py` — snapshot-, nod-, kant- och provenancekontrakt;
- `schemas/snapshot_diff.schema.json` — nuvarande minimala exportschema;
- `tests/test_binary_waterfall_compatibility.py` — regressioner för exakt, strukturell och inkompatibel jämförelse;
- `tests/test_binary_runtime_full.py` — grundläggande cross-snapshot-diff.

Kör fokuserade tester från Hex Editor-roten:

```powershell
python -m pytest tests\test_binary_waterfall_compatibility.py tests\test_binary_runtime_full.py -q
```

Vid felsökning, kontrollera i denna ordning:

1. att båda snapshots har samma formatplugin;
2. vilka policyfält som saknas eller skiljer sig;
3. de två sekvensmåtten och policytrösklarna;
4. om nod- och kant-ID:n verkligen är stabila över körningarna;
5. om `source.sha256` representerar rätt ingång på båda sidor;
6. om användaren egentligen förväntar sig en rå byte-range-diff, vilket den nuvarande tjänsten inte producerar.
