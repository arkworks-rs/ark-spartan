use ark_ec::CurveGroup;
use ark_std::rand::SeedableRng;
use digest::{ExtendableOutput, Input};
use rand_chacha::ChaCha20Rng;
use sha3::Shake256;
use std::io::Read;

#[derive(Debug)]
pub struct MultiCommitGens<G: CurveGroup> {
  pub n: usize,
  pub G: Vec<G::Affine>,
  pub h: G::Affine,
}

impl<G: CurveGroup> MultiCommitGens<G> {
  pub fn new(n: usize, label: &[u8]) -> Self {
    let mut shake = Shake256::default();
    shake.input(label);
    let mut buf = vec![];
    G::generator().serialize_compressed(&mut buf).unwrap();
    shake.input(buf);

    let mut reader = shake.xof_result();
    let mut seed = [0u8; 32];
    reader.read_exact(&mut seed).unwrap();
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut gens: Vec<G> = Vec::new();
    for _ in 0..n + 1 {
      gens.push(G::rand(&mut rng));
    }
    let gens: Vec<G::Affine> = CurveGroup::normalize_batch(gens.as_ref());

    MultiCommitGens {
      n,
      G: gens[..n].to_vec(),
      h: gens[n],
    }
  }

  pub fn clone(&self) -> Self {
    MultiCommitGens {
      n: self.n,
      h: self.h,
      G: self.G.clone(),
    }
  }

  pub fn split_at(&self, mid: usize) -> (Self, Self) {
    let (G1, G2) = self.G.split_at(mid);

    (
      MultiCommitGens {
        n: G1.len(),
        G: G1.to_vec(),
        h: self.h,
      },
      MultiCommitGens {
        n: G2.len(),
        G: G2.to_vec(),
        h: self.h,
      },
    )
  }
}

pub trait Commitments<G: CurveGroup>: Sized {
  fn commit(&self, blind: &G::ScalarField, gens_n: &MultiCommitGens<G>) -> G;
  fn batch_commit(inputs: &[Self], blind: &G::ScalarField, gens_n: &MultiCommitGens<G>) -> G;
}

impl<G: CurveGroup> Commitments<G> for G::ScalarField {
  fn commit(&self, blind: &G::ScalarField, gens_n: &MultiCommitGens<G>) -> G {
    assert_eq!(gens_n.n, 1);

    gens_n.G[0] * self + gens_n.h * blind
  }

  fn batch_commit(inputs: &[Self], blind: &G::ScalarField, gens_n: &MultiCommitGens<G>) -> G {
    assert_eq!(gens_n.n, inputs.len());
    G::msm(&gens_n.G, inputs).unwrap() + gens_n.h * blind
  }
}
