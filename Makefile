export ERLANG_MK ?= $(CURDIR)/erlang.mk

PROJECT = eauth
PROJECT_DESCRIPTION = Semi-sane auth{N,Z} for Erlang
PROJECT_VERSION = 0.1.0

DEPS	   = erlkit
dep_erlkit = git https://github.com/jflatow/erlkit.git

all:: $(ERLANG_MK)
$(ERLANG_MK):
	curl https://erlang.mk/erlang.mk | make -f -

include $(ERLANG_MK)
