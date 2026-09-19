"""
Feature encoding (Phase-6 §8, §9): logical feature values -> a stable numeric matrix.

Separated from extraction on purpose. Extraction understands evidence; encoding
understands numbers. Two properties matter more than anything else here:

* **Column order is a function of the schema, not of the data.** It is derived from
  `FEATURE_SPECS` and the declared vocabularies, so it cannot drift because one dataset
  happened to contain a value another did not. Training and inference therefore agree
  by construction rather than by convention.

* **No invented ordinality.** Categoricals become one-hot indicators. The only numeric
  encoding of an ordered category is `tls_version_ordinal`, which carries its written
  justification on the spec (`FeatureSpec.ordinal_justification`).

Unknown categorical values are routed to the vocabulary's `__other__` column. They never
create a column, shift the layout, or raise -- an unexpected cipher suite in the field
must degrade gracefully, not break analysis (§22, §35).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from securemailscope.ml.features import (
    FEATURE_SCHEMA_VERSION, FeatureGroup, FeatureKind, FeatureSpec, MISSING_FILL,
    MLFeatureVector, OTHER, SPEC_BY_ID,
)


@dataclass(frozen=True)
class EncodedMatrix:
    """Numeric matrix plus the metadata needed to interpret and reproduce it."""
    schema_version: str
    columns: Tuple[str, ...]
    rows: Tuple[Tuple[float, ...], ...]
    session_keys: Tuple[Optional[str], ...]
    column_to_feature: Dict[str, str]

    @property
    def shape(self) -> Tuple[int, int]:
        return (len(self.rows), len(self.columns))

    def to_dict(self) -> dict:
        return {"schema_version": self.schema_version, "columns": list(self.columns),
                "n_rows": len(self.rows), "n_columns": len(self.columns)}


class FeatureEncoder:
    """Deterministic one-hot + numeric encoder over a fixed schema."""

    def __init__(self, groups: Optional[Sequence[FeatureGroup]] = None,
                 exclude: Optional[Sequence[str]] = None) -> None:
        self.groups: Tuple[FeatureGroup, ...] = tuple(groups) if groups else tuple(FeatureGroup)
        self.exclude: frozenset = frozenset(exclude or ())
        self.specs: Tuple[FeatureSpec, ...] = tuple(
            s for s in SPEC_BY_ID.values()
            if s.group in self.groups and s.feature_id not in self.exclude)
        self.columns, self.column_to_feature = self._layout()

    # ---- layout -------------------------------------------------------------
    def _layout(self) -> Tuple[Tuple[str, ...], Dict[str, str]]:
        columns: List[str] = []
        owner: Dict[str, str] = {}
        # Sorted by feature id so the layout depends only on the schema.
        for spec in sorted(self.specs, key=lambda s: s.feature_id):
            if spec.kind is FeatureKind.CATEGORICAL:
                for value in spec.vocabulary:
                    col = f"{spec.feature_id}={value}"
                    columns.append(col)
                    owner[col] = spec.feature_id
            else:
                columns.append(spec.feature_id)
                owner[spec.feature_id] = spec.feature_id
                # Numerics that can be absent carry an explicit missingness indicator so
                # "not observed" is learnable and never confused with the fill value.
                if spec.kind is FeatureKind.NUMERIC and "missing" in spec.missing_policy:
                    col = f"{spec.feature_id}__missing"
                    columns.append(col)
                    owner[col] = spec.feature_id
        return tuple(columns), owner

    # ---- encoding -----------------------------------------------------------
    def encode_one(self, vector: MLFeatureVector) -> Tuple[float, ...]:
        if vector.schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"feature schema mismatch: vector {vector.schema_version} "
                f"!= encoder {FEATURE_SCHEMA_VERSION}")
        index = {c: 0.0 for c in self.columns}
        missing = set(vector.missing)
        for spec in self.specs:
            raw = vector.values.get(spec.feature_id)
            if spec.kind is FeatureKind.CATEGORICAL:
                value = str(raw) if raw is not None else OTHER
                col = f"{spec.feature_id}={value}"
                if col not in index:
                    # Unseen category: route to __other__ rather than dropping it.
                    col = f"{spec.feature_id}={OTHER}"
                if col in index:
                    index[col] = 1.0
            else:
                index[spec.feature_id] = (
                    float(raw) if isinstance(raw, (int, float)) else MISSING_FILL)
                flag = f"{spec.feature_id}__missing"
                if flag in index:
                    index[flag] = 1.0 if spec.feature_id in missing else 0.0
        return tuple(index[c] for c in self.columns)

    def encode(self, vectors: Sequence[MLFeatureVector]) -> EncodedMatrix:
        rows = tuple(self.encode_one(v) for v in vectors)
        return EncodedMatrix(
            schema_version=FEATURE_SCHEMA_VERSION,
            columns=self.columns,
            rows=rows,
            session_keys=tuple(v.session_key for v in vectors),
            column_to_feature=dict(self.column_to_feature),
        )

    def layout_signature(self) -> str:
        """Stable hash of the column layout, recorded in the model artifact so a model
        can refuse a matrix it was not trained against (§24)."""
        import hashlib
        return hashlib.sha256("\n".join(self.columns).encode()).hexdigest()[:16]
