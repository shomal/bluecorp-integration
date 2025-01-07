class CsvModel:
    def __init__(self, customerReference, loadId, containerType, itemCode, itemQuantity, itemWeight, street, city, state, postalCode, country):
        self.customerReference = customerReference
        self.loadId = loadId
        self.containerType = containerType
        self.itemCode =itemCode
        self.itemQuantity = itemQuantity
        self.itemWeight = itemWeight
        self.street = street
        self.city = city
        self.state = state
        self.postalCode = postalCode
        self.country = country
        
    @staticmethod
    def from_dict(data):
        return CsvModel(
            customerReference=data["CustomerReference"],
            loadId=data["LoadId"],
            containerType=data["ContainerType"],
            itemCode=data["ItemCode"],
            itemQuantity=data["ItemQuantity"],
            itemWeight=data["ItemWeight"],
            street=data["Street"],
            city=data["City"],
            state=data["State"],
            postalCode=data["PostalCode"],
            country=data["Country"]      
        )
    