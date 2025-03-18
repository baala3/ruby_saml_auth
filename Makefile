SP_HOST ?= https://ruby-saml-auth.test

puma-dev:
	brew install puma/puma/puma-dev
	sudo puma-dev -setup
	puma-dev -install
	echo "9292" > ~/.puma-dev/ruby-saml-auth

install:
	bundle install

run:
	(while ! nc -z localhost 9292; do sleep 0.1; done && open $(SP_HOST)) &
	puma -p 9292

stop:
	pkill -f puma
