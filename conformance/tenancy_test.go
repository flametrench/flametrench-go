// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

// Stateful conformance runners for all tenancy fixtures: admin-remove,
// change-role, invitation-accept, invitation-accept-binding, org-name-slug,
// self-leave, transfer-ownership.

package conformance

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/flametrench/flametrench-go/packages/ids"
	"github.com/flametrench/flametrench-go/packages/tenancy"
)

// classifyTenancyError maps a Go error to the fixture error class name.
func classifyTenancyError(err error) string {
	if errors.Is(err, tenancy.ErrNotFound) {
		return "NotFoundError"
	}
	if errors.Is(err, tenancy.ErrSoleOwner) {
		return "SoleOwnerError"
	}
	if errors.Is(err, tenancy.ErrAlreadyTerminal) {
		return "AlreadyTerminalError"
	}
	if errors.Is(err, tenancy.ErrOrgSlugConflict) {
		return "OrgSlugConflictError"
	}
	if errors.Is(err, tenancy.ErrForbidden) {
		return "ForbiddenError"
	}
	if errors.Is(err, tenancy.ErrRoleHierarchy) {
		return "RoleHierarchyError"
	}
	if errors.Is(err, tenancy.ErrInvitationNotPending) {
		return "InvitationNotPendingError"
	}
	if errors.Is(err, tenancy.ErrIdentifierMismatch) {
		return "IdentifierMismatchError"
	}
	if errors.Is(err, tenancy.ErrIdentifierBindingRequired) {
		return "IdentifierBindingRequiredError"
	}
	var pe *tenancy.PreconditionError
	if errors.As(err, &pe) {
		return "PreconditionError"
	}
	return "UnknownError:" + err.Error()
}

func assertTenancyStepError(t *testing.T, caseID, stepLabel string, expected map[string]any, err error) bool {
	t.Helper()
	wantClass, hasExpected := expected["error"].(string)
	if !hasExpected {
		if err != nil {
			t.Errorf("%s/%s: unexpected error: %v", caseID, stepLabel, err)
			return false
		}
		return true
	}
	if err == nil {
		t.Errorf("%s/%s: expected %s but got no error", caseID, stepLabel, wantClass)
		return false
	}
	got := classifyTenancyError(err)
	if got != wantClass {
		t.Errorf("%s/%s: error = %q, want %q (raw: %v)", caseID, stepLabel, got, wantClass, err)
		return false
	}
	return true
}

// makeUpdateOrgInput parses the partial-update semantics for UpdateOrg.
// A key present with a string value means set; present with null means clear;
// absent means leave unchanged.
func makeUpdateOrgInput(input map[string]any) tenancy.UpdateOrgInput {
	var in tenancy.UpdateOrgInput
	if nameRaw, ok := input["name"]; ok {
		if nameRaw == nil {
			in.ClearName = true
		} else if s, ok := nameRaw.(string); ok {
			in.Name = &s
		}
	}
	if slugRaw, ok := input["slug"]; ok {
		if slugRaw == nil {
			in.ClearSlug = true
		} else if s, ok := slugRaw.(string); ok {
			in.Slug = &s
		}
	}
	return in
}

// parsePreTuples converts the raw pre_tuples JSON value to []tenancy.PreTuple.
func parsePreTuples(raw any) []tenancy.PreTuple {
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]tenancy.PreTuple, 0, len(arr))
	for _, elem := range arr {
		m, ok := elem.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, tenancy.PreTuple{
			Relation:   strField(m, "relation"),
			ObjectType: strField(m, "object_type"),
			ObjectID:   strField(m, "object_id"),
		})
	}
	return out
}

func runTenancyStepCase(t *testing.T, c StepCase) {
	t.Helper()
	store := tenancy.NewInMemoryTenancyStore()
	captures := make(map[string]string)

	// Pre-create usr_ IDs for each named user in the preset.
	for _, name := range c.Users {
		id, err := ids.Generate("usr")
		if err != nil {
			t.Fatalf("%s: generate usr id for %q: %v", c.ID, name, err)
		}
		captures[name] = id
	}

	for stepIdx, rawStep := range c.Steps {
		stepLabel := fmt.Sprintf("step[%d]:%s", stepIdx, rawStep.Op)
		input := resolveInput(rawStep.Input, captures)
		expected := rawStep.Expected
		if expected == nil {
			expected = map[string]any{}
		}

		switch rawStep.Op {

		case "create_org":
			creator := strField(input, "creator")
			opts := tenancy.CreateOrgOptions{}
			if s := strPtr(input, "name"); s != nil {
				opts.Name = s
			}
			if s := strPtr(input, "slug"); s != nil {
				opts.Slug = s
			}
			result, err := store.CreateOrg(creator, opts)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					switch path {
					case "org.id":
						captures[varName] = result.Org.ID
					case "owner_membership.id":
						captures[varName] = result.OwnerMembership.ID
					}
				}
			}

		case "add_member":
			orgID := strField(input, "org_id")
			usrID := strField(input, "usr_id")
			role := tenancy.Role(strField(input, "role"))
			result, err := store.AddMember(orgID, usrID, role, nil)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					if path == "id" {
						captures[varName] = result.ID
					}
				}
			}

		case "admin_remove":
			memID := strField(input, "mem_id")
			adminUsrID := strField(input, "admin_usr_id")
			result, err := store.AdminRemove(memID, adminUsrID)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					if path == "removed_by" {
						if result.RemovedBy != nil {
							captures[varName] = *result.RemovedBy
						}
					}
				}
			}

		case "change_role":
			memID := strField(input, "mem_id")
			newRole := tenancy.Role(strField(input, "new_role"))
			result, err := store.ChangeRole(memID, newRole)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					switch path {
					case "id":
						captures[varName] = result.ID
					case "replaces":
						if result.Replaces != nil {
							captures[varName] = *result.Replaces
						}
					}
				}
			}

		case "self_leave":
			memID := strField(input, "mem_id")
			var transferTo *string
			if s := strPtr(input, "transfer_to"); s != nil {
				transferTo = s
			}
			_, err := store.SelfLeave(memID, transferTo)
			assertTenancyStepError(t, c.ID, stepLabel, expected, err)

		case "transfer_ownership":
			orgID := strField(input, "org_id")
			fromMemID := strField(input, "from_mem_id")
			toMemID := strField(input, "to_mem_id")
			_, err := store.TransferOwnership(orgID, fromMemID, toMemID)
			assertTenancyStepError(t, c.ID, stepLabel, expected, err)

		case "update_org":
			orgID := strField(input, "org_id")
			in := makeUpdateOrgInput(input)
			_, err := store.UpdateOrg(orgID, in)
			assertTenancyStepError(t, c.ID, stepLabel, expected, err)

		case "suspend_org":
			orgID := strField(input, "org_id")
			_, err := store.SuspendOrg(orgID)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "revoke_org":
			orgID := strField(input, "org_id")
			_, err := store.RevokeOrg(orgID)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "list_orgs":
			opts := tenancy.ListOrgsOptions{}
			if v, ok := input["limit"].(float64); ok {
				opts.Limit = int(v)
			}
			if s := strPtr(input, "cursor"); s != nil {
				opts.Cursor = s
			}
			if s := strPtr(input, "status"); s != nil {
				st := tenancy.Status(*s)
				opts.Status = &st
			}
			if s := strPtr(input, "query"); s != nil {
				opts.Query = s
			}
			page, err := store.ListOrgs(opts)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				// Capture next_cursor for multi-page tests.
				for varName, path := range rawStep.Captures {
					if path == "page.next_cursor" {
						if page.NextCursor != nil {
							captures[varName] = *page.NextCursor
						}
					}
				}
				// Validate expected result.
				if res, ok := expected["result"].(map[string]any); ok {
					// data_ids_in_order: ordered comparison.
					if wantRaw, ok := res["data_ids_in_order"]; ok {
						want := toStringSlice(wantRaw)
						for i, w := range want {
							if resolved, ok := resolveAny(w, captures).(string); ok {
								want[i] = resolved
							}
						}
						got := make([]string, len(page.Data))
						for i, o := range page.Data {
							got[i] = o.ID
						}
						if len(got) != len(want) {
							t.Errorf("%s/%s: list_orgs data len = %d, want %d (got %v want %v)",
								c.ID, stepLabel, len(got), len(want), got, want)
						} else {
							for i := range want {
								if got[i] != want[i] {
									t.Errorf("%s/%s: list_orgs data[%d] = %q, want %q",
										c.ID, stepLabel, i, got[i], want[i])
								}
							}
						}
					}
					// data_ids_unordered: set comparison.
					if wantRaw, ok := res["data_ids_unordered"]; ok {
						want := toStringSlice(wantRaw)
						for i, w := range want {
							if resolved, ok := resolveAny(w, captures).(string); ok {
								want[i] = resolved
							}
						}
						got := make([]string, len(page.Data))
						for i, o := range page.Data {
							got[i] = o.ID
						}
						wantSet := make(map[string]bool, len(want))
						for _, w := range want {
							wantSet[w] = true
						}
						gotSet := make(map[string]bool, len(got))
						for _, g := range got {
							gotSet[g] = true
						}
						if len(gotSet) != len(wantSet) {
							t.Errorf("%s/%s: list_orgs unordered len = %d, want %d (got %v want %v)",
								c.ID, stepLabel, len(gotSet), len(wantSet), got, want)
						} else {
							for w := range wantSet {
								if !gotSet[w] {
									t.Errorf("%s/%s: list_orgs missing id %q (got %v)", c.ID, stepLabel, w, got)
								}
							}
						}
					}
					// next_cursor assertion.
					if nc, ok := res["next_cursor"]; ok {
						if nc == nil {
							if page.NextCursor != nil {
								t.Errorf("%s/%s: list_orgs next_cursor = %q, want null", c.ID, stepLabel, *page.NextCursor)
							}
						} else if s, ok := nc.(string); ok {
							if page.NextCursor == nil {
								t.Errorf("%s/%s: list_orgs next_cursor = null, want non-nil (%q)", c.ID, stepLabel, s)
							}
						}
					}
				}
			}

		case "create_invitation":
			orgID := strField(input, "org_id")
			identifier := strField(input, "identifier")
			role := tenancy.Role(strField(input, "role"))
			invitedBy := strField(input, "invited_by")
			ttl := 86400
			if v, ok := input["ttl_seconds"].(float64); ok {
				ttl = int(v)
			}
			expiresAt := time.Now().Add(time.Duration(ttl) * time.Second)
			preTuples := parsePreTuples(input["pre_tuples"])
			result, err := store.CreateInvitation(orgID, identifier, role, invitedBy, expiresAt, preTuples)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					if path == "id" {
						captures[varName] = result.ID
					}
				}
			}

		case "accept_invitation":
			invID := strField(input, "inv_id")
			opts := tenancy.AcceptInvitationOptions{}
			if hasKey(input, "as_usr_id") {
				s := strPtr(input, "as_usr_id")
				opts.AsUsrID = s
			}
			if ai := strPtr(input, "accepting_identifier"); ai != nil {
				opts.AcceptingIdentifier = ai
			}
			result, err := store.AcceptInvitation(invID, opts)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}
			if err == nil {
				for varName, path := range rawStep.Captures {
					if path == "membership.usr_id" {
						captures[varName] = result.Membership.UsrID
					}
				}
			}

		case "decline_invitation":
			invID := strField(input, "inv_id")
			var asUsrID *string
			if s := strPtr(input, "as_usr_id"); s != nil {
				asUsrID = s
			}
			_, err := store.DeclineInvitation(invID, asUsrID)
			if !assertTenancyStepError(t, c.ID, stepLabel, expected, err) {
				return
			}

		case "assert_equal":
			actual := strField(input, "actual")
			exp := strField(input, "expected")
			if actual != exp {
				t.Errorf("%s/%s: assert_equal: %q != %q", c.ID, stepLabel, actual, exp)
			}

		case "assert_org_fields":
			orgID := strField(input, "org_id")
			org, err := store.GetOrg(orgID)
			if err != nil {
				t.Errorf("%s/%s: GetOrg(%q): %v", c.ID, stepLabel, orgID, err)
				return
			}
			if wantName, hasName := input["expected_name"]; hasName {
				if wantName == nil {
					if org.Name != nil {
						t.Errorf("%s/%s: name = %q, want null", c.ID, stepLabel, *org.Name)
					}
				} else {
					wantStr, _ := wantName.(string)
					if org.Name == nil {
						t.Errorf("%s/%s: name = null, want %q", c.ID, stepLabel, wantStr)
					} else if *org.Name != wantStr {
						t.Errorf("%s/%s: name = %q, want %q", c.ID, stepLabel, *org.Name, wantStr)
					}
				}
			}
			if wantSlug, hasSlug := input["expected_slug"]; hasSlug {
				if wantSlug == nil {
					if org.Slug != nil {
						t.Errorf("%s/%s: slug = %q, want null", c.ID, stepLabel, *org.Slug)
					}
				} else {
					wantStr, _ := wantSlug.(string)
					if org.Slug == nil {
						t.Errorf("%s/%s: slug = null, want %q", c.ID, stepLabel, wantStr)
					} else if *org.Slug != wantStr {
						t.Errorf("%s/%s: slug = %q, want %q", c.ID, stepLabel, *org.Slug, wantStr)
					}
				}
			}

		case "assert_subject_relations":
			subjectType := strField(input, "subject_type")
			subjectID := strField(input, "subject_id")
			wantRelations := toStringSlice(input["relations"])

			tuples, err := store.ListTuplesForSubject(subjectType, subjectID)
			if err != nil {
				t.Errorf("%s/%s: ListTuplesForSubject: %v", c.ID, stepLabel, err)
				return
			}
			gotRelations := make([]string, 0, len(tuples))
			for _, tup := range tuples {
				gotRelations = append(gotRelations, tup.Relation)
			}
			sort.Strings(gotRelations)
			wantSorted := make([]string, len(wantRelations))
			copy(wantSorted, wantRelations)
			sort.Strings(wantSorted)

			if len(gotRelations) != len(wantSorted) {
				t.Errorf("%s/%s: subject_relations = %v, want %v", c.ID, stepLabel, gotRelations, wantSorted)
			} else {
				for i := range wantSorted {
					if gotRelations[i] != wantSorted[i] {
						t.Errorf("%s/%s: subject_relations[%d] = %q, want %q (full: got %v want %v)",
							c.ID, stepLabel, i, gotRelations[i], wantSorted[i], gotRelations, wantSorted)
					}
				}
			}

		case "assert_invitation_status":
			invID := strField(input, "inv_id")
			wantStatus := tenancy.InvitationStatus(strField(input, "expected_status"))
			inv, err := store.GetInvitation(invID)
			if err != nil {
				t.Errorf("%s/%s: GetInvitation(%q): %v", c.ID, stepLabel, invID, err)
				return
			}
			if inv.Status != wantStatus {
				t.Errorf("%s/%s: invitation status = %q, want %q", c.ID, stepLabel, inv.Status, wantStatus)
			}

		default:
			t.Fatalf("%s: unknown op %q", c.ID, rawStep.Op)
		}
	}
}

func runTenancyFixture(t *testing.T, path string) {
	t.Helper()
	f := loadStepFixtureFile(t, path)
	for _, c := range f.Tests {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			runTenancyStepCase(t, c)
		})
	}
}

func TestAdminRemoveConformance(t *testing.T) {
	runTenancyFixture(t, filepath.Join("fixtures", "tenancy", "admin-remove.json"))
}

func TestChangeRoleConformance(t *testing.T) {
	runTenancyFixture(t, filepath.Join("fixtures", "tenancy", "change-role.json"))
}

func TestInvitationAcceptConformance(t *testing.T) {
	runTenancyFixture(t, filepath.Join("fixtures", "tenancy", "invitation-accept.json"))
}

func TestInvitationAcceptBindingConformance(t *testing.T) {
	runTenancyFixture(t, filepath.Join("fixtures", "tenancy", "invitation-accept-binding.json"))
}

func TestOrgNameSlugConformance(t *testing.T) {
	runTenancyFixture(t, filepath.Join("fixtures", "tenancy", "org-name-slug.json"))
}

func TestSelfLeaveConformance(t *testing.T) {
	runTenancyFixture(t, filepath.Join("fixtures", "tenancy", "self-leave.json"))
}

func TestTransferOwnershipConformance(t *testing.T) {
	runTenancyFixture(t, filepath.Join("fixtures", "tenancy", "transfer-ownership.json"))
}

func TestListOrgsConformance(t *testing.T) {
	runTenancyFixture(t, filepath.Join("fixtures", "tenancy", "list-orgs.json"))
}
