-- Explicit operator-enrolled node inventory. A checkout cannot mint
-- topology or trust a node key supplied by a customer or payment verifier.
CREATE TABLE elx_node_inventory (
 node_id uuid PRIMARY KEY,
 incarnation uuid NOT NULL,
 enabled boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (node_id,incarnation)
  REFERENCES elx_core_identities(node_id,incarnation)
);
CREATE TABLE elx_paid_profile_nodes (
 profile_id uuid NOT NULL REFERENCES elx_paid_profiles(id),
 node_id uuid NOT NULL REFERENCES elx_node_inventory(node_id),
 resource_id uuid NOT NULL,
 epoch bigint NOT NULL CHECK(epoch>0),
 PRIMARY KEY (profile_id,node_id),
 UNIQUE (node_id,resource_id),
 FOREIGN KEY (node_id,resource_id)
  REFERENCES elx_rate_grants(node_id,resource_id)
);
CREATE INDEX elx_paid_profile_nodes_node ON elx_paid_profile_nodes(node_id);
