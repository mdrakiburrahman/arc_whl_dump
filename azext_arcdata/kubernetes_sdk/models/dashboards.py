# coding: utf-8

"""
    Microsoft SQL Server Controller Service

    No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)  # noqa: E501

    OpenAPI spec version: v1.0.0

    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""

import pprint
import re  # noqa: F401

import six


class Dashboards(object):
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
        "node_metrics_url": "str",
        "sql_metrics_url": "str",
        "logs_url": "str",
    }

    attribute_map = {
        "node_metrics_url": "NodeMetricsUrl",
        "sql_metrics_url": "SqlMetricsUrl",
        "logs_url": "LogsUrl",
    }

    def __init__(
        self, node_metrics_url=None, sql_metrics_url=None, logs_url=None
    ):  # noqa: E501
        """Dashboards - a model defined in Swagger"""  # noqa: E501

        self._node_metrics_url = None
        self._sql_metrics_url = None
        self._logs_url = None
        self.discriminator = None

        if node_metrics_url is not None:
            self.node_metrics_url = node_metrics_url
        if sql_metrics_url is not None:
            self.sql_metrics_url = sql_metrics_url
        if logs_url is not None:
            self.logs_url = logs_url

    @property
    def node_metrics_url(self):
        """Gets the node_metrics_url of this Dashboards.  # noqa: E501


        :return: The node_metrics_url of this Dashboards.  # noqa: E501
        :rtype: str
        """
        return self._node_metrics_url

    @node_metrics_url.setter
    def node_metrics_url(self, node_metrics_url):
        """Sets the node_metrics_url of this Dashboards.


        :param node_metrics_url: The node_metrics_url of this Dashboards.  # noqa: E501
        :type: str
        """

        self._node_metrics_url = node_metrics_url

    @property
    def sql_metrics_url(self):
        """Gets the sql_metrics_url of this Dashboards.  # noqa: E501


        :return: The sql_metrics_url of this Dashboards.  # noqa: E501
        :rtype: str
        """
        return self._sql_metrics_url

    @sql_metrics_url.setter
    def sql_metrics_url(self, sql_metrics_url):
        """Sets the sql_metrics_url of this Dashboards.


        :param sql_metrics_url: The sql_metrics_url of this Dashboards.  # noqa: E501
        :type: str
        """

        self._sql_metrics_url = sql_metrics_url

    @property
    def logs_url(self):
        """Gets the logs_url of this Dashboards.  # noqa: E501


        :return: The logs_url of this Dashboards.  # noqa: E501
        :rtype: str
        """
        return self._logs_url

    @logs_url.setter
    def logs_url(self, logs_url):
        """Sets the logs_url of this Dashboards.


        :param logs_url: The logs_url of this Dashboards.  # noqa: E501
        :type: str
        """

        self._logs_url = logs_url

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
        if issubclass(Dashboards, dict):
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
        if not isinstance(other, Dashboards):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
