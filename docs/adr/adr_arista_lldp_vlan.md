# Arista LLDP VLAN

* **Title**: Arista's switches/routers to not give port tagging formation like Juniper's

* **Status**: proposed

* **Context**: We use tagging information (via lldpcli) to verify that the network port a director is connected has the correct VLANs. In lldp this is sent by optional TLV's In Arista POPs this information is not being sent.

* **Decision**: Carve out specific pops that are exceptions to this check so we can continue in Arista POPs that are tagged correctly but are not detected properly

* **Consequences**:
  * Adds complexity
  * Could cause problems if we bring up new directors that are not tagged properly, we will not detect properly

* **Tags**: xdp, arista, vlan
