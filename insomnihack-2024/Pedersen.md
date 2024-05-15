# The Large Pedersen Collider

## The Challenge

The goal was to find a collision in the Pedersen hash function (i.e., find distinct inputs that
yield the same output).

We had access to a running version of the code (a hashing oracle), as indicated in the `README.md`:

```Markdown
You do not need to go to the CERN to have collisions, simply using Pedersen hash should do the
trick.

`nc pedersen-log.insomnihack.ch 25192`

Test locally: `cargo run -r`
```

The implementation (in Rust) of the hash function was provided. All the interesting bits were in the
`main.rs` file:

```Rust
use starknet_curve::{curve_params, AffinePoint, ProjectivePoint};
use starknet_ff::FieldElement;
use std::ops::AddAssign;
use std::ops::Mul;
use std::time::Duration;
use std::thread::sleep;

mod private;

const SHIFT_POINT: ProjectivePoint = ProjectivePoint::from_affine_point(&curve_params::SHIFT_POINT);
const PEDERSEN_P0: ProjectivePoint = ProjectivePoint::from_affine_point(&curve_params::PEDERSEN_P0);
const PEDERSEN_P2: ProjectivePoint = ProjectivePoint::from_affine_point(&curve_params::PEDERSEN_P2);

fn perdersen_hash(x: &FieldElement, y: &FieldElement) -> FieldElement {
    let c1: [bool; 16] = private::C1;
    let c2: [bool; 16] = private::C2;

    let const_p0 = PEDERSEN_P0.clone();
    let const_p1 = const_p0.mul(&c1);
    let const_p2 = PEDERSEN_P2.clone();
    let const_p3 = const_p0.mul(&c2);
    
    // Compute hash of two field elements
    let x = x.to_bits_le();
    let y = y.to_bits_le();

    let mut acc = SHIFT_POINT;

    acc.add_assign(&const_p0.mul(&x[..248]));
    acc.add_assign(&const_p1.mul(&x[248..252]));
    acc.add_assign(&const_p2.mul(&y[..248]));
    acc.add_assign(&const_p3.mul(&y[248..252]));
    
    // Convert to affine
    let result = AffinePoint::from(&acc);

    // Return x-coordinate
    result.x
}

fn get_number() -> FieldElement {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line).unwrap();
    // Remove new line
    line.pop();
    let in_number = FieldElement::from_dec_str(&line).unwrap_or_else(|_| {
        println!("Error: bad number");
        std::process::exit(1)
    });
    in_number
}

fn main() {
    println!("Welcome in the Large Pedersen Collider\n");
    sleep(Duration::from_millis(500));
    println!("Enter the first number to hash:");
    let a1 = get_number();
    println!("Enter the second number to hash:");
    let b1 = get_number();
    let h1 = perdersen_hash(&a1, &b1);
    println!("Hash is {}", h1);

    println!("Enter the first number to hash:");
    let a2 = get_number();
    println!("Enter the second number to hash:");
    let b2 = get_number();
    
    if a1 == a2 && b1 == b2 {
        println!("Input must be different.");
        std::process::exit(1);
    }

    let h2 = perdersen_hash(&a2, &b2);
    println!("Hash is {}", h2);

    if h1 != h2 {
        println!("No collision.");
    } else {
        println!("Collision found, congrats here is the flag {}", private::FLAG);
    }
}
```

So we can almost run the code locally, but the `private` module is missing. Looking at the rest of
the code, we can infer that the private module contains the flag and two mysterious constants: `C1`
and `C2`, which we can initialize arbitrarily for now:

```Rust
mod private {
    pub const FLAG: &str = "INS{this_is_the_flag}";
    pub const C1: [bool; 16] = [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
    pub const C2: [bool; 16] = [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
}
```

We then see in the main function that we actually need two numbers to compute one hash value. We
must therefore find four numbers `a1`, `b1`, `a2`, `b2`, such that `(a1 == a2 && b1 == b2)` is
false, but `perdersen_hash(&a1, &b1) == perdersen_hash(&a2, &b2)`.

A first important observation here is that `b1` can be equal to `b2`, as long as `a1` is different
from `a2`.

## The Theory

There are two non-standard imports: `starknet_curve` and `starknet_ff`, which are both part of the
`starknet-rs` library: <https://github.com/xJonathanLEI/starknet-rs>.

The documentation tells us how the Pedersen hash function is supposed to be implemented:
<https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html>.

Normally, $H$ is a Pedersen hash on two field elements, $(a, b)$ represented as 252-bit integers,
defined as follows (after some renaming to keep the math consistent with the code):

$$
H(a, b) = [S + a_\textit{low} \cdot P_0 + a_\textit{high} \cdot P_1 + b_\textit{low} \cdot P_2 + b_\textit{high} \cdot P_3]_x
$$

where

- $a_\textit{low}$ is the 248 low bits of $a$ (same for $b$);
- $a_\textit{high}$ is the 4 high bits of $a$ (same for $b$);
- $[P]_x$ denotes the $x$ coordinate of an elliptic-curve point $P$;
- $S$, $P_0$, $P_1$, $P_2$, $P_3$, are constant points on the elliptic curve, derived from the
decimal digits of $\pi$.

But looking at the challenge's implementation, we see that the constant points are actually related:

- $P_1 = P_0 \cdot C_1$
- $P_3 = P_2 \cdot C_2$

Given the above equations, we can rewrite the hash function as follows:

$$
H(a, b) = [S + (a_\textit{low} + a_\textit{high} \cdot C_1) \cdot P0 + (b_\textit{low} + b_\textit{high} \cdot C_2) \cdot P2]_x
$$

Since we've established that we can keep $b$ constant, let's find a pair $a$ and $a'$ such that

$$
a_\textit{low} + a_\textit{high} \cdot C_1 = a_\textit{low}' + a_\textit{high}' \cdot C_1
$$

Given the linear nature of these equations, there is a range of solutions. If $a_\textit{low}$ is
increased by some $\delta$, then $a_\textit{high}$ can be decreased by $\delta/C_1$ to keep the term
$(a_\textit{low} + a_\textit{high} \cdot C_1) \cdot P0$ unchanged.

A straightforward solution is to pick $\delta = C_1$, which implies that if we increase
$a_\textit{low}$ by $C_1$ and decrease $a_\textit{high}$ by 1, we have a collision.

## The Practice

Now in theory we know how to find a collision, but we don't actually know `C1` and `C2`. Since they
are just 16 bits long, let's bruteforce them! Or at least one of them... As we don't need different
values for `b1` and `b2`, we can leave them at 0 and thus `C2` is not needed. You could bruteforce
`C1` with a piece of code that looks like this:

```Rust
// Try all possible values of c1
for i in 0..(1 << 16) {
    let mut c1 = [false; 16];
    for j in 0..16 {
        c1[j] = (i >> j) & 1 == 1;
    }

    let const_p0 = PEDERSEN_P0.clone();
    let const_p1 = const_p0.mul(&c1);
    let const_p2 = PEDERSEN_P2.clone();
    let const_p3 = const_p0.mul(&c2);

    let x = x.to_bits_le();
    let y = y.to_bits_le();

    let mut acc = SHIFT_POINT;

    acc.add_assign(&const_p0.mul(&x[..248]));
    acc.add_assign(&const_p1.mul(&x[248..252]));
    acc.add_assign(&const_p2.mul(&y[..248]));
    acc.add_assign(&const_p3.mul(&y[248..252]));

    let result = AffinePoint::from(&acc);

    // Check if the result is the expected hash
    if result.x == FieldElement::from_dec_str("3476785985550489048013103508376451426135678067229015498654828033707313899675").unwrap() {
        // Convert c1 to decimal
        let mut c1_dec = 0;
        for j in 0..16 {
            c1_dec |= (c1[j] as u16) << j;
        }
        println!("Bruteforce successful, c1 = {}", c1_dec);
        break;
    }
}
```

For this to work, we need to query the hashing oracle with $a_\textit{high} \ne 0$ (otherwise `C1`
does not play any role in the computation of the final result) and $b_\textit{high} = 0$. For
example, we could set the first number to
$2^{248} = 452312848583266388373324160190187140051835877600158453279131187530910662656$ and the
second number to $0$, and obtain a hash value of
$3476785985550489048013103508376451426135678067229015498654828033707313899675$.

We then find by bruteforce that $C_1 = 24103$.

## The Solution

Now that we have everything we need, the final solution is:

```
Enter the first number to hash: 452312848583266388373324160190187140051835877600158453279131187530910662656
Enter the second number to hash: 0
Hash is: 3476785985550489048013103508376451426135678067229015498654828033707313899675

Enter the first number to hash: 24103
Enter the second number to hash: 0
Hash is: 3476785985550489048013103508376451426135678067229015498654828033707313899675
```

This works because we start with $a_\textit{low} = 0$ and $a_\textit{high} = 1$ (i.e., $2^{248}$),
and then we increase $a_\textit{low}$ by $C_1$ and decrease $a_\textit{high}$ by $1$ to obtain
24103.

Submitting such a collision to `nc pedersen-log.insomnihack.ch 25192` gives us the `INS{...}` flag
(which we forgot to save, sorry).
