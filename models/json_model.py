class Item:
    def __init__(self, itemCode, quantity, cartonWeight):
        self.itemCode = itemCode
        self.quantity = quantity
        self.cartonWeight = cartonWeight

    @staticmethod
    def from_dict(data):
        return Item(
            itemCode=data["itemCode"],
            quantity=data["quantity"],
            cartonWeight=data["cartonWeight"]
        )


class Container:
    def __init__(self, loadId, containerType, items):
        self.loadId = loadId
        self.containerType = containerType
        self.items = [Item.from_dict(item) for item in items]

    @staticmethod
    def from_dict(data):
        return Container(
            loadId=data["loadId"],
            containerType=data["containerType"],
            items=data["items"]
        )


class DeliveryAddress:
    def __init__(self, street, city, state, postalCode, country):
        self.street = street
        self.city = city
        self.state = state
        self.postalCode = postalCode
        self.country = country

    @staticmethod
    def from_dict(data):
        return DeliveryAddress(
            street=data["street"],
            city=data["city"],
            state=data["state"],
            postalCode=data["postalCode"],
            country=data["country"]
        )


class ReadyForDispatch:
    def __init__(self, controlNumber, salesOrder, containers, deliveryAddress):
        self.controlNumber = controlNumber
        self.salesOrder = salesOrder
        self.containers = [Container.from_dict(container) for container in containers]
        self.deliveryAddress = DeliveryAddress.from_dict(deliveryAddress)

    @staticmethod
    def from_dict(data):
        return ReadyForDispatch(
            controlNumber=data["controlNumber"],
            salesOrder=data["salesOrder"],
            containers=data["containers"],
            deliveryAddress=data["deliveryAddress"]
        )
