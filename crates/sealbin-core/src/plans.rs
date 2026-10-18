//! Plans as data and the plan-change downgrade rule (D13, #15, #16).
//!
//! Plan limits, feature flags and the downgrade rule live here. This module
//! is pure and depends on no harness types (D1).

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::Effect;

/// Free seals per month during launch promo (D13).
pub const LAUNCH_PROMO_SEALS_PER_MONTH: u32 = 1_000;

/// Standard free seals per month outside promo (D13).
pub const STANDARD_FREE_SEALS_PER_MONTH: u32 = 250;

/// The four sealbin plans (D13, #15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    /// 3 agents, 1,000 seals/month launch (250 standard), 5 MB max seal, 24h max TTL.
    #[default]
    Free,
    /// $19/mo: 10 agents, unlimited seals (fair use), 100 MB max seal, 30d max TTL, audit log.
    Pro,
    /// $49/mo: 50 agents, custom domain, policies & roles, 1-year audit.
    Team,
    /// Self-host: unlimited agents, seals, size, TTL (Workers request limits only).
    SelfHost,
}

impl Plan {
    /// Parses a plan name (case-insensitive).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "free" => Some(Self::Free),
            "pro" => Some(Self::Pro),
            "team" => Some(Self::Team),
            "selfhost" | "self-host" => Some(Self::SelfHost),
            _ => None,
        }
    }

    /// The canonical plan identifier.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
            Self::Team => "team",
            Self::SelfHost => "selfhost",
        }
    }

    /// The numerical ceilings and features for this plan (D13).
    #[must_use]
    #[allow(clippy::duration_suboptimal_units)]
    pub fn limits(&self) -> PlanLimits {
        match self {
            Self::Free => PlanLimits {
                max_agents: Some(3),
                seals_per_month: Some(LAUNCH_PROMO_SEALS_PER_MONTH),
                max_seal_bytes: Some(5_000_000), // 5 MB
                max_ttl: Some(Duration::from_secs(24 * 3600)),
                default_ttl: Duration::from_secs(24 * 3600),
                audit_retention: None,
                features: PlanFeatures {
                    key_scopes: false,
                    audit_log: false,
                    custom_domain: false,
                    policies: false,
                    region_choice: false,
                },
            },
            Self::Pro => PlanLimits {
                max_agents: Some(10),
                seals_per_month: None,             // unlimited, fair use
                max_seal_bytes: Some(100_000_000), // 100 MB
                max_ttl: Some(Duration::from_secs(30 * 24 * 3600)),
                default_ttl: Duration::from_secs(24 * 3600),
                audit_retention: Some(Duration::from_secs(30 * 24 * 3600)),
                features: PlanFeatures {
                    key_scopes: true,
                    audit_log: true,
                    custom_domain: false,
                    policies: false,
                    region_choice: false,
                },
            },
            Self::Team => PlanLimits {
                max_agents: Some(50),
                seals_per_month: None,             // unlimited, fair use
                max_seal_bytes: Some(100_000_000), // 100 MB
                max_ttl: Some(Duration::from_secs(30 * 24 * 3600)),
                default_ttl: Duration::from_secs(24 * 3600),
                audit_retention: Some(Duration::from_secs(365 * 24 * 3600)),
                features: PlanFeatures {
                    key_scopes: true,
                    audit_log: true,
                    custom_domain: true,
                    policies: true,
                    region_choice: true,
                },
            },
            Self::SelfHost => PlanLimits {
                max_agents: None,
                seals_per_month: None,
                max_seal_bytes: None,
                max_ttl: None,
                default_ttl: Duration::from_secs(24 * 3600),
                audit_retention: None,
                features: PlanFeatures {
                    key_scopes: true,
                    audit_log: true,
                    custom_domain: true,
                    policies: true,
                    region_choice: true,
                },
            },
        }
    }
}

/// Numerical limits and durations for a plan (D13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanLimits {
    /// Maximum number of active API keys / agents, or None for unlimited.
    pub max_agents: Option<u32>,
    /// Maximum seals created per calendar month, or None for unlimited.
    pub seals_per_month: Option<u32>,
    /// Maximum ciphertext size in bytes, or None for unlimited.
    pub max_seal_bytes: Option<u64>,
    /// Maximum TTL allowed at creation, or None for unlimited.
    pub max_ttl: Option<Duration>,
    /// Default TTL when none is requested: 24 hours across all plans.
    pub default_ttl: Duration,
    /// Audit log retention duration, if the plan includes audit logs.
    pub audit_retention: Option<Duration>,
    /// Feature availability flags.
    pub features: PlanFeatures,
}

/// Plan feature flags (D13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct PlanFeatures {
    /// Per-agent key scopes.
    pub key_scopes: bool,
    /// Audit log access.
    pub audit_log: bool,
    /// Custom domain support.
    pub custom_domain: bool,
    /// Policies and role-based access.
    pub policies: bool,
    /// Region choice.
    pub region_choice: bool,
}

/// The plan change and downgrade rule (D13, #15, #16).
///
/// Existing seals keep their size and TTL; existing agent keys keep working;
/// new creations follow the new plan. Therefore, no destructive effects
/// on existing seals or keys are emitted.
#[must_use]
pub fn on_plan_change(old: Plan, new: Plan) -> Vec<Effect> {
    let _ = (old, new);
    // Downgrade keeps existing seals and keys intact; new creations will be
    // evaluated against `new.limits()`.
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_round_trip() {
        assert_eq!(Plan::parse("free"), Some(Plan::Free));
        assert_eq!(Plan::parse("PRO"), Some(Plan::Pro));
        assert_eq!(Plan::parse("Team"), Some(Plan::Team));
        assert_eq!(Plan::parse("selfhost"), Some(Plan::SelfHost));
        assert_eq!(Plan::parse("self-host"), Some(Plan::SelfHost));
        assert_eq!(Plan::parse("unknown"), None);

        assert_eq!(Plan::Free.as_str(), "free");
        assert_eq!(Plan::Pro.as_str(), "pro");
        assert_eq!(Plan::Team.as_str(), "team");
        assert_eq!(Plan::SelfHost.as_str(), "selfhost");
    }

    #[test]
    #[allow(clippy::duration_suboptimal_units)]
    fn limits_match_d13_specification() {
        let free = Plan::Free.limits();
        assert_eq!(free.max_agents, Some(3));
        assert_eq!(free.max_seal_bytes, Some(5_000_000));
        assert_eq!(free.seals_per_month, Some(1_000));
        assert_eq!(free.max_ttl, Some(Duration::from_secs(24 * 3600)));
        assert!(!free.features.audit_log);
        assert!(!free.features.key_scopes);

        let pro = Plan::Pro.limits();
        assert_eq!(pro.max_agents, Some(10));
        assert_eq!(pro.max_seal_bytes, Some(100_000_000));
        assert_eq!(pro.seals_per_month, None);
        assert_eq!(pro.max_ttl, Some(Duration::from_secs(30 * 24 * 3600)));
        assert!(pro.features.audit_log);
        assert!(pro.features.key_scopes);

        let team = Plan::Team.limits();
        assert_eq!(team.max_agents, Some(50));
        assert_eq!(team.max_seal_bytes, Some(100_000_000));
        assert!(team.features.custom_domain);
        assert!(team.features.policies);

        let self_host = Plan::SelfHost.limits();
        assert_eq!(self_host.max_agents, None);
        assert_eq!(self_host.max_seal_bytes, None);
        assert_eq!(self_host.seals_per_month, None);
    }

    #[test]
    fn downgrade_rule_preserves_existing_seals_and_keys() {
        // Downgrade from Pro to Free emits no destructive effects on existing seals
        let effects = on_plan_change(Plan::Pro, Plan::Free);
        assert!(
            effects.is_empty(),
            "on_plan_change must not emit destructive effects on existing seals"
        );

        // New seals follow the new plan's limits
        let new_limits = Plan::Free.limits();
        assert_eq!(new_limits.max_seal_bytes, Some(5_000_000));
        assert_eq!(new_limits.max_agents, Some(3));
    }
}
