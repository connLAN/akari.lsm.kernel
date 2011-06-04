akari-objs := audit.o autobind.o capability.o condition.o domain.o environ.o file.o gc.o group.o memory.o mount.o network.o policy_io.o proc_if.o realpath.o signal.o util.o load_policy.o lsm.o
obj-m += akari.o

$(obj)/tomoyo2c: $(obj)/tomoyo2c.c
	@echo Compiling built-in policy generator for TOMOYO 1.8.x.
	@$(HOSTCC) $(HOSTCFLAGS) -o $(obj)/tomoyo2c $(obj)/tomoyo2c.c

$(obj)/policy/profile.conf:
	@echo Creating an empty policy/profile.conf
	@touch $@

$(obj)/policy/exception_policy.conf:
	@echo Creating an empty policy/exception_policy.conf
	@touch $@

$(obj)/policy/domain_policy.conf:
	@echo Creating an empty policy/domain_policy.conf
	@touch $@

$(obj)/policy/manager.conf:
	@echo Creating an empty policy/manager.conf
	@touch $@

$(obj)/policy/stat.conf:
	@echo Creating an empty policy/stat.conf
	@touch $@

$(obj)/builtin-policy.h: $(obj)/policy/profile.conf $(obj)/policy/exception_policy.conf $(obj)/policy/domain_policy.conf $(obj)/policy/manager.conf $(obj)/policy/stat.conf $(obj)/tomoyo2c
	@echo Generating built-in policy for TOMOYO 1.8.x.
	@$(obj)/tomoyo2c profile < $(obj)/policy/profile.conf > $@
	@$(obj)/tomoyo2c exception_policy < $(obj)/policy/exception_policy.conf >> $@
	@$(obj)/tomoyo2c domain_policy < $(obj)/policy/domain_policy.conf >> $@
	@$(obj)/tomoyo2c manager < $(obj)/policy/manager.conf >> $@
	@$(obj)/tomoyo2c stat < $(obj)/policy/stat.conf >> $@

$(obj)/policy_io.o: $(obj)/builtin-policy.h
