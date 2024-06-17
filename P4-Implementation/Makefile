all: compile start

compile:
	${SDE_INSTALL}/bin/bf-p4c --target tofino --arch tna --create-graphs -o /home/<user>/SEET+/P4-Implementation/output seet.p4
	sudo cp /home/<user>/SEET+/P4-Implementation/output/seet.conf ${SDE_INSTALL}/share/p4/targets/tofino/seet+.conf

start:
	${SDE}/run_switchd.sh -p seet+
