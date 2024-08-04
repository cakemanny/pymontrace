


# Thank you: https://stackoverflow.com/a/2839113/4591158
mach_excServer.c: excserver.defs
	mig $<
	$(RM) mach_excUser.c mach_exc.h

.PHONY: clean
clean:
	$(RM) *.o

.PHONY: maintainer-clean
maintainer-clean: clean
	$(RM) mach_excServer.c mach_excUser.c mach_exc.h *.o
