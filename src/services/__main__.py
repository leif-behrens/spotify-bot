"""Entry point for running Discovery Service as module"""

from .discovery_service import SpotifyDiscoveryService


def main():
    service = SpotifyDiscoveryService()
    service.run()


if __name__ == "__main__":
    main()
