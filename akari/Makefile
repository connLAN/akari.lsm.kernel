akari-objs := audit.o autobind.o capability.o condition.o domain.o environ.o file.o gc.o group.o memory.o mount.o network.o policy_io.o proc_if.o realpath.o signal.o util.o load_policy.o lsm.o
obj-m += akari-test.o akari.o

$(obj)/policy/profile.conf:
	@mkdir -p $(obj)/policy/
	@echo Creating an empty policy/profile.conf
	@touch $@

$(obj)/policy/exception_policy.conf:
	@mkdir -p $(obj)/policy/
	@echo Creating an empty policy/exception_policy.conf
	@touch $@

$(obj)/policy/domain_policy.conf:
	@mkdir -p $(obj)/policy/
	@echo Creating an empty policy/domain_policy.conf
	@touch $@

$(obj)/policy/manager.conf:
	@mkdir -p $(obj)/policy/
	@echo Creating an empty policy/manager.conf
	@touch $@

$(obj)/policy/stat.conf:
	@mkdir -p $(obj)/policy/
	@echo Creating an empty policy/stat.conf
	@touch $@

$(obj)/builtin-policy.h: $(obj)/policy/profile.conf $(obj)/policy/exception_policy.conf $(obj)/policy/domain_policy.conf $(obj)/policy/manager.conf $(obj)/policy/stat.conf
	@echo Generating built-in policy for TOMOYO 1.8.x.
	@echo "static char ccs_builtin_profile[] __initdata =" > $@.tmp
	@sed -e 's/\\/\\\\/g' -e 's/\"/\\"/g' -e 's/\(.*\)/"\1\\n"/' < $(obj)/policy/profile.conf >> $@.tmp
	@echo "\"\";" >> $@.tmp
	@echo "static char ccs_builtin_exception_policy[] __initdata =" >> $@.tmp
	@sed -e 's/\\/\\\\/g' -e 's/\"/\\"/g' -e 's/\(.*\)/"\1\\n"/' < $(obj)/policy/exception_policy.conf >> $@.tmp
	@echo "\"\";" >> $@.tmp
	@echo "static char ccs_builtin_domain_policy[] __initdata =" >> $@.tmp
	@sed -e 's/\\/\\\\/g' -e 's/\"/\\"/g' -e 's/\(.*\)/"\1\\n"/' < $(obj)/policy/domain_policy.conf >> $@.tmp
	@echo "\"\";" >> $@.tmp
	@echo "static char ccs_builtin_manager[] __initdata =" >> $@.tmp
	@sed -e 's/\\/\\\\/g' -e 's/\"/\\"/g' -e 's/\(.*\)/"\1\\n"/' < $(obj)/policy/manager.conf >> $@.tmp
	@echo "\"\";" >> $@.tmp
	@echo "static char ccs_builtin_stat[] __initdata =" >> $@.tmp
	@sed -e 's/\\/\\\\/g' -e 's/\"/\\"/g' -e 's/\(.*\)/"\1\\n"/' < $(obj)/policy/stat.conf >> $@.tmp
	@echo "\"\";" >> $@.tmp
	@mv $@.tmp $@

$(obj)/policy_io.o: $(obj)/builtin-policy.h $(obj)/config.h

.o: $(obj)/config.h
