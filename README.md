# group
Group traits for abelian groups in additive notation, designed to resemble the cryptographic/mathematics definition as accurately as possible.
Traits are hierarchical in nature, and higher-level traits embody more specific properties on top of the ones below. 
This allows us to capture shared logic between cryptographic group in the most generic way possible, so that schemes and protocols could be designed (e.g. [`maurer`](https://github.com/dwallet-labs/maurer)) to work with any group, 
including dynamic, unknown order groups like Paillier, and static, prime-order groups like elliptic curves (e.g. secp256k1.) 

These traits were designed with the security concerned of high-level protocols in mind, and as such are constant-time by default. 

Another key addition is [`GroupElement::PublicParameters`] which captures the relevant information to hash into the transcript, as required by Fiat-Shamir transforms.
Another important security (and functionality) aspect of the public parameters is the fact they allow us to separate the group element [`GroupElement`] from its value [`GroupElement::Value`]; the former is a runtime representation which encodes necessary information for group operations whereas
the latter solely represents the value which can be serialized and transported over the wire, to later be instantiated into the former using the group's public parameter [`GroupElement::PublicParameters`]. 
This is important since group operation must always succeed, however, we must also prevent malicious players from forcing us to use wrong groups. 
For example, if a malicious prover can force the verifier to use a Paillier group for a modulus they generated themselves (and thus know how to factor,) they can 
bypass verification for incorrect claims. Instead, the verifier should only receive the value of group elements, and instantiate the group element using *their own public parameters*, which assures operating in the correct group.

# Security
We have gone through a rigorous internal auditing process throughout development, requiring the approval of two additional cryptographers and one additional programmer in every pull request. 
That being said, this code has not been audited by a third party yet; use it at your own risk.

# Releases
This code has no official releases yet, and we reserve the right to change some of the public API until then.
