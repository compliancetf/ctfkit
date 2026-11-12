# Evidence pack PDF assets

`RenderPDF` embeds these files with `go:embed`.

| File | Source | License |
|---|---|---|
| `AtkinsonHyperlegibleNext-Regular.ttf`, `AtkinsonHyperlegibleNext-Bold.ttf` | `fonts/ttf/` of [googlefonts/atkinson-hyperlegible-next](https://github.com/googlefonts/atkinson-hyperlegible-next) at commit `7925f50f649b3813257faf2f4c0b381011f434f1`, unchanged | SIL Open Font License 1.1, see `OFL.txt` |
| `AtkinsonHyperlegibleMono-Regular.ttf` | `fonts/ttf/` of [googlefonts/atkinson-hyperlegible-next-mono](https://github.com/googlefonts/atkinson-hyperlegible-next-mono) at commit `154d50362016cc3e873eb21d242cd0772384c8f9`, unchanged | SIL Open Font License 1.1, see `OFL.txt` |
| `logo.png` | the compliance.tf logo for light backgrounds (`logo-light.svg`), rasterised with `rsvg-convert -h 240` (about 670 dpi at the 9 mm height the cover prints it) | compliance.tf's own mark |

Atkinson Hyperlegible Next and Mono are by the Braille Institute of America. The PDF embeds a
subset of each font, as the OFL allows. Only Regular, Bold and Mono Regular are kept, to hold the
binary size down.
