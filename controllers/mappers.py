# mappers.py
class ContainerTypeMapper:
    CONTAINER_TYPE_MAP = {
        "20RF": "REF20",
        "40RF": "REF40",
        "20HC": "HC20",
        "40HC": "HC40"
    }

    @staticmethod
    def map_container_type(container_type):
        return ContainerTypeMapper.CONTAINER_TYPE_MAP.get(container_type, container_type)
