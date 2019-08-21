Cosmos DB Collections - Resize Throughput with On/Off Hours
===========================================================

With Azure Cosmos DB, you pay for the throughput you provision. Sometimes it's known that Cosmos DB will not be
utilized during certain hours of the day. To save cost during those times, it's useful for the higher throughput
collections to be resized down to a lower throughput.

Combining the following filters and actions will allow us to resize and restore the throughput state of Cosmos DB
collections according to hours of the day:

    Filters:

    * ``onhour``: allows us to filter actions so they execute only during on hours on the parent Cosmos DB Account. The filter can be applied using the ``parent`` filter for the Cosmos DB Account.
    * ``offhour``: allows us to filter actions so they execute only during off hours. The filter can be applied using the ``parent`` filter for the Cosmos DB Account.
    * ``offer``: allows us to filter collections with high throughputs (in this example, greater than 800)

    Actions:

    * ``store-throughput-state``: stores the current state of the collections in a tag
    * ``replace-offer``: resizes collections during off hours (in this example, down to 400)
    * ``restore-throughput-state``: restores the throughput state of the collections from the tag provided in the ``store-throughput-state`` action

Note: The tag provided to ``store-throughput-state`` and ``restore-throughput-state`` must be the same.

.. code-block:: yaml

    policies:
      - name: restore-collections-throughput-during-on-hours
        resource: azure.cosmosdb-collections
        filters:
          - type: parent
            filter:
                type: onhour
                default_tz: pt
        actions:
          - type: restore-throughput-state
            state-tag: on-hours-throughput

      - name: store-collections-throughput-and-resize-during-off-hours
        resource: azure.cosmosdb-collections
        filters:
          - type: parent
            filter:
                type: offhour
                default_tz: pt
          - type: offer
            key: content.offerThroughput
            op: gt
            value: 800
        actions:
          - type: store-throughput-state
            state-tag: on-hours-throughput
          - type: replace-offer
            throughput: 400
