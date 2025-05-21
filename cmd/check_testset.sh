#!/bin/bash

for function in $(grep "func" main.go | grep -v main\( | awk '{print $4}'| awk -F'(' '{print $1}')
do
	grep -i test$function service-now-plugin_test.go > /dev/null
	if test $? == 1
	then
		echo "Function $function doesn't have tests"
	fi
done
