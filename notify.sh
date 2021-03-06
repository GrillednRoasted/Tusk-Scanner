#Detect the name of the display in use
display=":$(ls /tmp/.X11-unix/* | sed 's#/tmp/.X11-unix/X##' | head -n 1)"

#Detect the user using such display
user=$(who | grep '('$display')' | awk '{print $1}' | head -n 1)

#Detect the id of the user
uid=$(id -u $user)

sudo -u $user DISPLAY=$display DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus /usr/bin/notify-send "$@"
