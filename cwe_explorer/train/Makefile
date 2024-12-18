include config.Makefile

CWE_JSON=$(shell echo $(CWE) | sed -E 's/^|$$/"/g ; s/  */", "/g')

ACTIVE_DIRS=$(shell jq -r '.[$(CWE_JSON)].id[]' data/cwe.json)

CFG_DIR=data/$(CONF_NAME)/$(REGPACK)/cfg
CONF_DIR=data/$(CONF_NAME)/$(REGPACK)/m$(MERGE_BY)bl$(BLOCK_LEN)pl$(MAX_PATH_LEN)s$(MAX_SUCCESSORS)
PATHS_FNAME=paths-$(CONF_DESC).npz
BIN=data/$(CONF_NAME)/bin

# Reasonable default is to restart with parallelism until you reach memory-intensive targets
# Preserve intermediate files by specifying intermediate targets explicitly
all:
	make -j$(JOBS) cfgs paths
	make datasets models config

binaries: $(patsubst %,$(BIN)/%/good,$(ACTIVE_DIRS)) $(patsubst %,$(BIN)/%/bad,$(ACTIVE_DIRS))
cfgs: $(patsubst %,$(CFG_DIR)/%.pickle.gz,$(ACTIVE_DIRS))

PATHS=$(patsubst %,$(CONF_DIR)/path/%.npz,$(ACTIVE_DIRS))
paths: $(PATHS)
datasets: $(shell echo $(CWE) | xargs -n1 printf "$(CONF_DIR)/ds/%s/train-x.mmap " )

MODELS=$(shell for i in $(CWE) ; do printf "$(CONF_DIR)/model/$$i.ubj" ; done)
models: $(MODELS)

config: $(CONF_DIR)/config.json

$(CONF_DIR)/ds/%/train-x.mmap: $(PATHS)
	mkdir -p "$(@D)"
	./make-dataset.py --cwe "$*" --inp "$(CONF_DIR)/path/" --out "$(@D)"

$(CONF_DIR)/model/%.ubj: $(CONF_DIR)/ds/%/train-x.mmap
	mkdir -p "$(@D)"
	./train-xgb.py --inp "$(<D)" --out "$@"

$(BIN)/%/bad:
	mkdir -p "$(@D)"
	CFLAGS="-DOMITGOOD $(CFLAGS)" make -C "data/juliet/$*" clean build
	find "data/juliet/$*/build" -mindepth 1 -type f -executable -exec mv {} "$(BIN)/$*/bad" \;

$(BIN)/%/good: $(BIN)/%/bad
	mkdir -p "$(@D)"
	CFLAGS="-DOMITBAD $(CFLAGS)" make -C "data/juliet/$*" clean build
	find "data/juliet/$*/build" -mindepth 1 -type f -executable -exec mv {} "$(BIN)/$*/good" \;

$(CFG_DIR)/%.pickle.gz: $(BIN)/%/good $(BIN)/%/bad
	mkdir -p "$(@D)"
	./cfg.py --good "$(BIN)/$*/good" --bad "$(BIN)/$*/bad" --out "$@" --registers "$(REGPACK)"

$(CONF_DIR)/path/%.npz: $(CFG_DIR)/%.pickle.gz
	mkdir -p "$(@D)"
	./paths.py --inp $^ --out $@ \
				--max-path-len "$(MAX_PATH_LEN)" \
				--merge-by "$(MERGE_BY)" \
				--block-len "$(BLOCK_LEN)" \
				--max-successors "$(MAX_SUCCESSORS)"

$(CONF_DIR)/config.json:
	printf '{ "REGPACK" : "$(REGPACK)", "MERGE_BY":$(MERGE_BY), "BLOCK_LEN":$(BLOCK_LEN), "MAX_PATH_LEN":$(MAX_PATH_LEN), "MAX_SUCCESSORS":$(MAX_SUCCESSORS) }' \
		> $@

.PHONY: dependencies cfgs paths models config clean clean-binaries clean-cfgs clean-paths clean-models clean-config

clean-binaries:
	rm -f $(BIN)/*/good
	rm -f $(BIN)/*/bad

clean-cfgs:
	rm -f ./$(CFG_DIR)/*

clean-paths:
	rm -f ./$(CONF_DIR)/path/*

clean-models:
	rm -f ./$(CONF_DIR)/model/*

clean-datasets:
	rm -fr ./$(CONF_DIR)/ds/*

clean-config:
	rm -f $(CONF_DIR)/config.json

clean: clean-binaries clean-cfgs clean-paths clean-models clean-datasets clean-config
