class Statistics:

    def __init__(self) -> None:
        self.__ip_sources: dict[str, int] = {}

    @property
    def ip_sources(self) -> dict[str, int]:
        return self.__ip_sources