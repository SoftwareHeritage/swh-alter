GENERATED_IMAGES = \
	$(shell printf "inventory-%02d.svg\n" $$(seq 1 12)) \
	mark.svg \
	dataset.svg \
	recovery-bundle.opt.svg

all: $(GENERATED_IMAGES)

%.svg: %.dot
	dot -Tsvg $< -o $@

%.opt.svg: %.svg
	inkscape --export-text-to-path --export-plain-svg --export-type=svg --export-filename=- $< | scour --enable-comment-stripping > $@

.PHONY: clean

clean:
	rm -f $(GENERATED_IMAGES) $(INVENTORY_FRAMES)
