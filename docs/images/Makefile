GENERATED_IMAGES = \
	$(shell printf "inventory-%02d.svg\n" $$(seq 1 12)) \
	mark.svg \
	dataset.svg

all: $(GENERATED_IMAGES)

%.svg: %.dot
	dot -Tsvg $< -o $@

.PHONY: clean

clean:
	rm -f $(GENERATED_IMAGES) $(INVENTORY_FRAMES)
