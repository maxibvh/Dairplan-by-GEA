# Reverse Engineering einer Lizenzprüfung – Methodik-Dokumentation

**Fach:** Reverse Engineering / Statische Binäranalyse
**Analyseobjekt:** `DP_Data.dll` (DairyPlan C21, WestfaliaSurge/GEA)
**Werkzeug:** Ghidra (statischer Decompiler)
**Autor:** Max A.

---

## 1. Ziel und Kontext

Ziel dieser Arbeit ist **nicht** das Erzeugen von Schlüsseln, sondern das
*Verstehen und Dokumentieren*, wie eine reale, kommerzielle Windows-Software
ihre Lizenzprüfung aufbaut. Die Software fragt beim Start einen
„Software-Schlüssel" ab; die Aufgabe war, mit statischer Analyse
nachzuvollziehen, **wo** diese Logik liegt und **wie** sie strukturiert ist.

Die Analyse steht beispielhaft für eine typische Reverse-Engineering-Aufgabe:
Aus einer kompilierten Binärdatei ohne Quellcode die innere Funktionsweise
eines Teilsystems rekonstruieren.

---

## 2. Werkzeuge und Einrichtung

| Werkzeug | Zweck |
|---|---|
| `file` | Dateityp und Architektur bestimmen |
| `strings` | lesbare Zeichenketten extrahieren |
| `c++filt` | „gemanglede" C++-Symbolnamen demanglen |
| **Ghidra** | Disassembler + Decompiler (Hauptwerkzeug) |

Die DLL wurde als **PE32, Intel 80386 (32-bit)** identifiziert – damit steht
die Ghidra-Importeinstellung fest (x86, 32-bit, little-endian).

---

## 3. Methodik Schritt für Schritt

### 3.1 Symbol-Übersicht vor Ghidra verschaffen

Bevor man Ghidra öffnet, lohnt sich ein schneller Blick auf die Symbole.
C++-Compiler kodieren Klassen- und Methodennamen in die Exporttabelle
(„name mangling"); `c++filt` macht sie wieder lesbar:

```bash
strings DP_Data.dll | c++filt | grep -i security
```

So entsteht eine Landkarte der relevanten Klassen, **bevor** man eine Zeile
Assembly liest. In diesem Fall traten u. a. Klassen rund um die
Schlüssel-/Prüflogik zutage, was die weitere Suche fokussiert hat.

**Lerneffekt:** Die Symboltabelle ist der schnellste Einstieg. Mangled Names
wie `?Foo@Bar@@QBEHXZ` verraten bereits Klasse (`Bar`), Methode (`Foo`) und
grob die Signatur.

### 3.2 Import und Auto-Analyse in Ghidra

1. `File → Import File` → `DP_Data.dll`
2. Format **Portable Executable (PE)**, Sprache **x86 / 32 / little**
3. `Analysis → Auto Analyze` mit Standardoptionen

Die Auto-Analyse erkennt Funktionsgrenzen, stellt Querverweise (XREFs) her
und benennt bekannte Bibliotheksaufrufe.

### 3.3 Funktionen gezielt finden

Im **Symbol Tree** (links) unter *Functions* per Filter nach einem
Methodennamen suchen. Wichtig: Es gibt zwei Trefferarten, die man
auseinanderhalten muss:

| Treffer | Bedeutung |
|---|---|
| `ds "..."` (Code Unit beginnt mit `ds`) | nur der **String** des Namens im Datenbereich |
| Eintrag vom Typ **Function** | die **tatsächliche Funktion** mit Code |

Nur der Function-Eintrag öffnet im Decompiler lesbaren Pseudocode.

**Lerneffekt (häufiger Anfängerfehler):** „Search Memory" nach dem Namen
findet nur den Namensstring, nicht die Funktion. Der richtige Weg führt über
Symbol Tree → Functions oder die Symbol Table.

### 3.4 Disassembly und Decompiler gemeinsam lesen

Ghidra zeigt links das **Listing** (x86-Assembly) und rechts den
**Decompiler** (C-ähnlicher Pseudocode). Beide Ansichten ergänzen sich:
Der Decompiler gibt die Struktur, das Listing die Gewissheit über die
tatsächlichen Instruktionen.

### 3.5 Datenreferenzen verfolgen

Konstanten wie Format-Strings erscheinen im Code als `DAT_xxxxxxxx`.
Per Doppelklick springt man zur Adresse; mit Taste **`A`** definiert Ghidra
rohe Bytes als String. So ließen sich z. B. `sprintf`-Formatstrings und damit
das Ausgabeformat eindeutig bestimmen.

**Lerneffekt:** Ein einzelnes Byte `46h` im Datenbereich ist erst dann als
`'F'` (Beginn von `"FAT32"`) erkennbar, wenn man Ghidra anweist, die Stelle
als String zu interpretieren.

---

## 4. Fallbeispiel: Assembly lesen lernen

Das lehrreichste Einzelstück war eine kleine Bit-Transformationsfunktion.
Sie eignet sich perfekt, um das Lesen von x86-Assembly zu üben, weil sie
kurz ist und nur arithmetisch-logische Instruktionen enthält.

### 4.1 Das Listing

```asm
MOV   ECX, dword ptr [ESP + param_1]   ; 1. Argument laden
MOV   EAX, dword ptr [ESP + param_2]   ; 2. Argument laden
ADD   ECX, EAX                         ; beide addieren
MOV   EAX, ECX                         ; Summe kopieren
AND   ECX, 0xeeeeeeee                  ; Maske A auf eine Kopie
AND   EAX, 0x11111111                  ; Maske B auf die andere Kopie
SHL   EAX, 0x4                          ; linksschieben um 4 Bit
ADD   EAX, ECX                         ; beide Teile wieder vereinen
AND   EAX, 0x7fffffff                  ; oberstes Bit abschneiden
RET                                     ; Rückgabe in EAX
```

### 4.2 Wie man das liest

Schritt für Schritt übersetzt:

- Zwei Parameter werden vom Stack (`[ESP + …]`) in Register geladen.
- `ADD` bildet ihre Summe.
- Die Summe wird **zweimal maskiert**: einmal mit `0x11111111`
  (selektiert das unterste Bit jeder 4-Bit-Gruppe), einmal mit `0xEEEEEEEE`
  (die übrigen drei Bits jeder Gruppe). Zusammen decken beide Masken alle
  Bits ab.
- `SHL EAX, 4` verschiebt den selektierten Anteil um eine Nibble-Position.
- Beide Anteile werden addiert, das Vorzeichenbit per `AND 0x7FFFFFFF`
  entfernt.
- Der Rückgabewert steht per Konvention in `EAX`.

### 4.3 Verifikation im Decompiler

Ghidras Decompiler bestätigt die Handübersetzung:

```c
return (p1 + p2 & 0x11111111) * 0x10
     + (p1 + p2 & 0xEEEEEEEE) & 0x7FFFFFFF;
```

(`* 0x10` ist dasselbe wie `SHL …, 4`.)

**Lerneffekt:** `AND` mit einer Bitmaske = „selektiere diese Bits";
`SHL n` = Multiplikation mit 2ⁿ; `AND 0x7FFFFFFF` = Vorzeichenbit löschen.
Das sind Muster, die in fast jeder Prüfsummen- oder Hash-ähnlichen Routine
wiederkehren.

---

## 5. Rekonstruierte Programmstruktur (Erkenntnisse)

Durch Verfolgen der XREFs ließ sich die Aufrufkette der Lizenzprüfung
grob kartieren:

```
Lizenzprüfung (oberste Prüfroutine)
        │
        ├─ ermittelt einen Installations-Fingerprint
        │     (basiert auf dem Zeitstempel einer Datei + Dateisystemtyp,
        │      NICHT auf fester Hardware)
        │
        ├─ verrechnet ihn mit einem optionsabhängigen Code
        │     (die im Installer gewählten Module/Kapazität fließen ein)
        │
        └─ vergleicht das Ergebnis mit der Benutzereingabe
```

Bemerkenswerte Design-Entscheidungen, die die Analyse sichtbar gemacht hat:

- **Installations- statt Hardwarebindung:** Der Fingerprint stammt aus dem
  Erstellungsdatum einer Datei, nicht aus einer Festplatten-Seriennummer.
  Das macht ihn stabil gegenüber Hardwaretausch, aber abhängig vom
  Dateisystem (FAT32 speichert Lokalzeit, NTFS UTC – die Software
  korrigiert das explizit).
- **Optionsabhängigkeit:** Die gekauften Module sind als Bitmaske kodiert
  und gehen in die Berechnung ein – die Prüfung ist dadurch an den
  Lizenzumfang gekoppelt.
- **Zwei Schlüsselformate:** ein älteres kurzes Format und ein neueres
  20-stelliges Format mit eingebauter **Prüfziffer** (Quersumme mod 9),
  das Tippfehler bei der Eingabe abfängt.

---

## 6. Reflexion

Was diese Aufgabe methodisch gezeigt hat:

1. **Top-down statt bottom-up.** Erst die Symboltabelle als Landkarte, dann
   gezielt einzelne Funktionen – nicht blind durch das Disassembly scrollen.
2. **Decompiler ist Hypothese, Listing ist Beweis.** Der Pseudocode leitet,
   aber bei kritischen Stellen muss man die echten Instruktionen gegenlesen.
3. **Datenfluss folgen.** XREFs und Datenreferenzen sind der rote Faden, der
   isolierte Funktionen zu einem verständlichen Gesamtbild verknüpft.
4. **Kleine Funktionen sind die beste Übung.** Die Bit-Transformation aus
   Abschnitt 4 ist ein ideales Lehrbeispiel, um x86-Grundinstruktionen sicher
   lesen zu lernen.

---

## 7. Haftungsausschluss

Diese Dokumentation ist eine **akademische Analyse zu Lehrzwecken**. Sie
beschreibt die *Methodik* der statischen Binäranalyse am Beispiel einer
Lizenzprüfung und dient dem Verständnis von Reverse-Engineering-Techniken,
nicht der Umgehung von Kopierschutz.
