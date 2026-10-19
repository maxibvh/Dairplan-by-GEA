# Reverse Engineering einer Lizenzprüfung – Methodik

Akademische Dokumentation einer statischen Binäranalyse mit **Ghidra**,
am Beispiel der Lizenzprüfung von DairyPlan C21 (WestfaliaSurge/GEA).

> **Fokus dieser Arbeit:** das *Wie* des Reverse Engineering – Ghidra-Workflow,
> Disassembly lesen, Funktionen und Datenflüsse rekonstruieren. Es geht um die
> Analysemethodik, nicht um das Erzeugen von Schlüsseln.

## Inhalt

| Datei | Beschreibung |
|---|---|
| [`docs/METHODIK_Reverse_Engineering.md`](docs/METHODIK_Reverse_Engineering.md) | Vollständige Methodik-Dokumentation |

## Behandelte Techniken

- Symbol-Extraktion aus einer PE-DLL (`strings`, `c++filt`, Name-Mangling)
- Import und Auto-Analyse in Ghidra (x86, 32-bit)
- Funktionen über den Symbol Tree finden (Function vs. Datenstring)
- x86-Disassembly lesen: `AND`/`SHL`/`ADD` und Bitmasken verstehen
- Decompiler-Pseudocode gegen das Listing verifizieren
- Datenreferenzen (`DAT_…`) auflösen und als String interpretieren
- Aufrufketten über XREFs zu einem Gesamtbild verknüpfen

## Werkzeuge

Ghidra · `strings` · `c++filt` · `file` · `od`

## Haftungsausschluss

Analyse zu Lehrzwecken. Beschreibt die Methodik statischer Binäranalyse,
nicht die Umgehung von Kopierschutz.


## Kontakt:
Anfragen bitte an:

## mexotaternos.sicherung@gmail.com
