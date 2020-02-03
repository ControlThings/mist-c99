#!/bin/bash

# This script starts many instances of the example Mist app in rapid sucession.
# The script is used to study wish core's issues when starting many apps in rapid succession.

maxServices=95
i=0;
while ((i++ < $maxServices )); do
    echo Starting: $i
    TEST_INSTANCE_NAME="instance"$i ./example-mist-app &
    #sleep 1 #We used to need a pause here - but no longer when we increased the listen() backlog in wish-core
done


sleep 30
#echo "Stopping test, killing example mist apps"
#killall example-mist-app
