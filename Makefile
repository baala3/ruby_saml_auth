
SP_HOST ?= https://ruby-saml-auth.test

setup:
	brew install puma/puma/puma-dev
	sudo puma-dev -setup
	puma-dev -install
	echo "9292" > ~/.puma-dev/ruby-saml-auth

run:
	sleep 1 && open $(SP_HOST) &
	puma -p 9292

stop:
	pkill -f puma
