# Nii Simple Server

Simpleserver is a simple file server, that serves the folder you run it from. Generates a self signed certificate in memory for https.

## Options

- -**unsafe**: runs simpleserver in unencrypted mode 

`simpleserver -unsafe`

- -**password**: uses basicauth for authentication. Username is ignored.

`simpleserver -password super-hard-password`

- -**port**: change the port simpleserver serves from

`simpleserver -port 9999`