# Abstract

AutoDriver is an automatic generator for fuzz-drivers
with the ability to pass complex objects between functions within a fuzz-target.
However, its current implementation relies on the default,
non-structure aware mutator suite of AFL++.
This limitation results in a high occurrence of crashes
caused by incorrect usage of the fuzz driver and a significant number of wasted fuzz cycles.
We introduce a custom, structure-aware mutator for AFL++,
specifically designed to generate the expected input structure of AutoDriver.
By integrating this mutator, we expedite initial coverage exploration,
enable deliberate utilization of AutoDriver-specific functionalities,
and reduce the overall number of crashes logged due to structurally invalid input.
To evaluate the effectiveness of our custom mutator,
we compare it against the default mutator suite of AFL++ in a fuzzing-campaign
with five well-known library targets.
Our results demonstrate that the integration of a custom mutator
presents a viable approach for enhancing AutoDriver's performance.
We outline further research opportunities aimed at surpassing the performance of the default AFL++ mutator suite,
enabling AutoDriver to produce better overall results in the library fuzzing domain.

---
Unfortunately I am unable to publish the full thesis at this time,
as it contains yet unpublished research from my thesis supervisor.
This repository merely contains the source code of the custom mutator,
without any AutoDriver generated fuzz-drivers required for its operation.
