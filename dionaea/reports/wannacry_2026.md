# WannaCry in the Wild — 2026

Cluster analysis of WannaCry samples captured by the Dionaea honeypot sensor.

---

## 1. Summary

The Dionaea sensor captured 285 suspicious binaries during the analysis window, of which 269 classified as WannaCry propagation-module samples, 14 as a generic Linux bot family, and 2 as unclassified. This document covers the methodology used to identify and cluster the WannaCry samples and what the resulting cluster structure says about how the worm is still propagating nine years after its original 2017 outbreak.

Tooling: `hunter.py` (sample analysis — string extraction, entropy, PE timestamp, IOC matching, family classification, and Jaccard-similarity clustering, all in `dionaea/`).

## 2. Data source

Dionaea captured all 269 samples via SMB, the same vector used by the original 2017 outbreak (MS17-010 / EternalBlue). Each sample was pulled from a distinct connection: different source IP, different timestamp, different SMB session.

## 3. Why these are classified as WannaCry

Several independent signals agree across all 269 samples:

- **IOC strings.** Every sample contains the propagation-module marker (`mssecsvr.exe`), the persistence-component marker (`tasksche.exe`), the loader DLL name (`launcher.dll`), and SMB/MS17-010-related artifacts. None of these strings appear in any other classified family in this dataset.
- **File size.** All samples fall in the 5.1–5.3 MB range, consistent with the known WannaCry loader DLL.
- **PE structure.** PE32 DLLs with the expected `.text`/`.rdata`/`.data`/`.reloc` section layout and the same characteristic import set (`CreateFileA`, `WriteFile`, `LoadResource`, `CreateProcessA`).
- **PE compile timestamp.** All samples carry a build timestamp of 11 May 2017 (within a few minutes), matching the original WannaCry build date — meaning these are unmodified binaries, not later recompiles.
- **Entropy.** First-256KB entropy in the 6.8–7.4 range, consistent with a partially packed PE, matching the known WannaCry loader.

## 4. Why 269 separate samples rather than one

Each capture has a distinct SHA-256, meaning these are 269 separate binary instances rather than 269 copies of the same file. Combined with the fact that each was delivered over a different SMB session, from a different source IP, at a different time, this indicates 269 separate infected hosts independently attempting to propagate — not a single source repeatedly hitting the sensor. The binary-level differences between samples (padding, section layout, resource placement) are consistent with artifacts introduced during network delivery rather than deliberate modification of the payload logic.

## 5. Clustering result

Running the 269 WannaCry-classified samples through `hunter.py`'s Jaccard-similarity clustering (threshold 0.4, based on extracted strings) produced a single cluster containing all 269 samples, connected as one component in the resulting similarity graph.

```
=== Family: WannaCry ===
Samples: 269
Clusters: 1
```

This is a strong signal of genetic homogeneity: the population of WannaCry samples currently circulating and being captured by this sensor is, at the string level, a single unmodified variant rather than several diverging strains.

## 6. Why WannaCry is still active in 2026

A few factors plausibly explain continued propagation nearly a decade after the original outbreak:

- A meaningful population of unpatched or end-of-life Windows installations (Windows 7, Server 2008, embedded/industrial systems) remains reachable over SMB, often inside closed networks that nonetheless expose SMB externally.
- WannaCry is a self-propagating worm rather than a trojan: it requires no user interaction to scan for and infect new hosts.
- Infected industrial or low-IT-maintenance hosts can run for years without reboot or patching, continuing to scan and infect.
- The underlying MS17-010 (EternalBlue) vulnerability, despite its age, remains present on enough internet-facing hosts to sustain propagation.

## 7. Conclusion

The 269 captures represent ongoing, live activity rather than residual noise, and the clustering result indicates this activity stems from a single unmodified version of the original payload rather than a forked or actively maintained variant. Nine years on, WannaCry continues to circulate in its original form, sustained by the long tail of unpatched, internet-facing SMB hosts.

---

*Generated from Dionaea honeypot data, SSHLab Research. See `dionaea/hunter.py` for the analysis tooling.*
