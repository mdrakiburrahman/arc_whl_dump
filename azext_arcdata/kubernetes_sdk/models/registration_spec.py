# coding: utf-8

"""
    Controller API

    No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)  # noqa: E501

    OpenAPI spec version: v1.0.0
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""

import pprint

import six


class RegistrationSpec(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        "uid": "str",
        "instance_name": "str",
        "instance_type": "str",
        "location": "str",
        "resource_group_name": "str",
        "subscription_id": "str",
        "instance_namespace": "str",
        "service_name": "str",
        "vcores": "str",
        "create_timestamp": "string",
        "update_timestamp": "string",
        "connection_mode": "string",
        "billing_mode": "string",
        "properties": "string",
    }

    attribute_map = {
        "uid": "uid",
        "instance_name": "instanceName",
        "instance_type": "instanceType",
        "location": "location",
        "resource_group_name": "resourceGroupName",
        "subscription_id": "subscriptionId",
        "instance_namespace": "instanceNamespace",
        "service_name": "serviceName",
        "vcores": "vcores",
        "create_timestamp": "createTimeStamp",
        "update_timestamp": "updateTimeStamp",
        "connection_mode": "connectionMode",
        "billing_mode": "billingMode",
        "properties": "properties",
    }

    def __init__(
        self,
        uid=None,
        instance_name=None,
        instance_type=None,
        location=None,
        resource_group_name=None,
        subscription_id=None,
        instance_namespace=None,
        service_name=None,
        vcores=None,
        create_timestamp=None,
        update_timestamp=None,
        connection_mode=None,
        billing_mode=None,
        properties=None,
    ):  # noqa: E501
        """RegistrationSpec - a model defined in Swagger
        :param instance_namespace:
        :param service_name:
        """  # noqa: E501
        self._uid = None
        self._instance_name = None
        self._instance_type = None
        self._location = None
        self._resource_group_name = None
        self._subscription_id = None
        self._create_timestamp = None
        self._update_timestamp = None
        self._connection_mode = None
        self._billing_mode = None
        self._properties = None
        self.discriminator = None
        if uid is not None:
            self.uid = uid
        if instance_name is not None:
            self.instance_name = instance_name
        if instance_type is not None:
            self.instance_type = instance_type
        if location is not None:
            self.location = location
        if resource_group_name is not None:
            self.resource_group_name = resource_group_name
        if subscription_id is not None:
            self.subscription_id = subscription_id
        if instance_namespace is not None:
            self.instance_namespace = instance_namespace
        if service_name is not None:
            self.service_name = service_name
        if vcores is not None:
            self.vcores = vcores
        if create_timestamp is not None:
            self.create_timestamp = create_timestamp
        if update_timestamp is not None:
            self.update_timestamp = update_timestamp
        if connection_mode is not None:
            self.connection_mode = connection_mode
        if billing_mode is not None:
            self.billing_mode = billing_mode
        if properties is not None:
            self.properties = properties

    @property
    def uid(self):
        """Gets the uid of this RegistrationSpec.  # noqa: E501
        :return: The uid of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._uid

    @uid.setter
    def uid(self, uid):
        """Sets the uid of this RegistrationSpec.
        :param uid: The uid of this RegistrationSpec.  # noqa: E501
        :type: str
        """
        self._uid = uid

    @property
    def instance_name(self):
        """Gets the instance_name of this RegistrationSpec.  # noqa: E501


        :return: The instance_name of this RegistrationSpec.  # noqa: E501
        :type: str
        """
        return self._instance_name

    @instance_name.setter
    def instance_name(self, instance_name):
        """Sets the instance_name of this RegistrationSpec.


        :param instance_name: The instance_name of this RegistrationSpec.  # noqa: E501
        :type: str
        """

        self._instance_name = instance_name

    @property
    def instance_type(self):
        """Gets the instance_type of this RegistrationSpec.  # noqa: E501


        :return: The instance_type of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._instance_type

    @instance_type.setter
    def instance_type(self, instance_type):
        """Sets the instance_type of this RegistrationSpec.


        :param instance_type: The instance_type of this RegistrationSpec.  # noqa: E501
        :type: str
        """

        self._instance_type = instance_type

    @property
    def location(self):
        """Gets the location of this RegistrationSpec.  # noqa: E501


        :return: The location of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._location

    @location.setter
    def location(self, location):
        """Sets the location of this RegistrationSpec.


        :param location: The location of this RegistrationSpec.  # noqa: E501
        :type: str
        """

        self._location = location

    @property
    def resource_group_name(self):
        """Gets the resource_group_name of this RegistrationSpec.  # noqa: E501


        :return: The resource_group_name of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._resource_group_name

    @resource_group_name.setter
    def resource_group_name(self, resource_group_name):
        """Sets the resource_group_name of this RegistrationSpec.


        :param resource_group_name: The resource_group_name of this RegistrationSpec.  # noqa: E501
        :type: str
        """

        self._resource_group_name = resource_group_name

    @property
    def subscription_id(self):
        """Gets the subscription_id of this RegistrationSpec.  # noqa: E501


        :return: The subscription_id of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._subscription_id

    @subscription_id.setter
    def subscription_id(self, subscription_id):
        """Sets the subscription_id of this RegistrationSpec.


        :param subscription_id: The subscription_id of this RegistrationSpec.  # noqa: E501
        :type: str
        """

        self._subscription_id = subscription_id

    @property
    def instance_namespace(self):
        """Gets the instance_namespace of this RegistrationSpec.  # noqa: E501


        :return: The instance_namespace of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._instance_namespace

    @instance_namespace.setter
    def instance_namespace(self, instance_namespace):
        """Sets the instance_namespace of this RegistrationSpec.


        :param instance_namespace: The subscription_id of this RegistrationSpec.  # noqa: E501
        :type: str
        """

        self._instance_namespace = instance_namespace

    @property
    def service_name(self):
        """Gets the service_name of this RegistrationSpec.  # noqa: E501


        :return: The service_name of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._service_name

    @service_name.setter
    def service_name(self, service_name):
        """Sets the service_name of this RegistrationSpec.


        :param service_name: The service_name of this RegistrationSpec.  # noqa: E501
        :type: str
        """

        self._service_name = service_name

    @property
    def vcores(self):
        """Gets the vcores of this RegistrationSpec.  # noqa: E501


        :return: The vcores of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._vcores

    @vcores.setter
    def vcores(self, vcores):
        """Sets the vcores of this RegistrationSpec.


        :param vcores: The vcores of this RegistrationSpec.  # noqa: E501
        :type: str
        """

        self._vcores = vcores

    @property
    def create_timestamp(self):
        """Gets the create timestamp of this RegistrationSpec.  # noqa: E501
        :return: The create timestamp of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._create_timestamp

    @create_timestamp.setter
    def create_timestamp(self, create_timestamp):
        """Sets the create timestamp of this RegistrationSpec.
        :param create_timestamp: The create timestamp of this RegistrationSpec.  # noqa: E501
        :type: str
        """
        self._create_timestamp = create_timestamp

    @property
    def update_timestamp(self):
        """Gets the update timestamp of this RegistrationSpec.  # noqa: E501
        :return: The update timestamp of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._update_timestamp

    @update_timestamp.setter
    def update_timestamp(self, update_timestamp):
        """Sets the update timestamp of this RegistrationSpec.
        :param update_timestamp: The update timestamp of this RegistrationSpec.  # noqa: E501
        :type: str
        """
        self._update_timestamp = update_timestamp

    @property
    def connection_mode(self):
        """Gets the connection_mode of this RegistrationSpec.  # noqa: E501
        :return: The connection_mode of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._connection_mode

    @connection_mode.setter
    def connection_mode(self, connection_mode):
        """Sets the connection_mode of this RegistrationSpec.
        :param connection_mode The connection_mode of this RegistrationSpec.  # noqa: E501
        :type: str
        """
        self._connection_mode = connection_mode

    @property
    def billing_mode(self):
        """Gets the billing_mode of this RegistrationSpec.  # noqa: E501
        :return: The billing_mode of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._billing_mode

    @billing_mode.setter
    def billing_mode(self, billing_mode):
        """Sets the billing_mode of this RegistrationSpec.
        :param billing_mode The billing_mode of this RegistrationSpec.  # noqa: E501
        :type: str
        """
        self._billing_mode = billing_mode

    @property
    def properties(self):
        """Gets the properties of this RegistrationSpec.  # noqa: E501
        :return: The properties of this RegistrationSpec.  # noqa: E501
        :rtype: str
        """
        return self._properties

    @properties.setter
    def properties(self, properties):
        """Sets the properties of this RegistrationSpec.
        :param properties: The properties of this RegistrationSpec.  # noqa: E501
        :type: str
        """
        self._properties = properties

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(
                    map(
                        lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                        value,
                    )
                )
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(
                    map(
                        lambda item: (item[0], item[1].to_dict())
                        if hasattr(item[1], "to_dict")
                        else item,
                        value.items(),
                    )
                )
            else:
                result[attr] = value
        if issubclass(RegistrationSpec, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, RegistrationSpec):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
