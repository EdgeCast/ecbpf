# xdp sampler common

Data structures shared among parts of the XDP packet sampling pipeline.

## Development

For local development, please follow these steps:
1. If you are on a linux host, you may have to disconnect from the VPN (due to NAT limitations).
2. Update the `*.proto` files (as needed).
3. Run `make container` to build a development container and connect to it.
4. Inside the container, select a subdirectory and `make` it.
5. Commit the changes to git and hope that CI approves :)
