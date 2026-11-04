"""ADONAI Cyber-Range Controller & Ground-Truth Evaluation Harness."""
import datetime
import json
import time
import uuid
from backend.detection_engine import DeterministicDetectionEngine
from backend.security import log_audit

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

class CyberRangeController:
    """Manages the 1,000 simulated endpoints, safe scenario execution, deterministic replay, and evaluation metrics."""

    STATE = {
        "range_status": "READY",  # READY, RUNNING, PAUSED, STOPPED
        "active_run_id": None,
        "last_scenario_code": None,
        "network_isolation_verified": True,
    }

    def __init__(self, conn):
        self.conn = conn
        self.engine = DeterministicDetectionEngine(conn)

    def control_range(self, action: str) -> dict:
        action = action.upper()
        ts = now_iso()
        if action == "PAUSE":
            self.STATE["range_status"] = "PAUSED"
            self.conn.execute("UPDATE SimulationRun SET status = 'PAUSED', updated_at = ? WHERE status = 'RUNNING'", (ts,))
        elif action == "RESUME":
            self.STATE["range_status"] = "RUNNING"
            self.conn.execute("UPDATE SimulationRun SET status = 'RUNNING', updated_at = ? WHERE status = 'PAUSED'", (ts,))
        elif action == "STOP":
            self.STATE["range_status"] = "STOPPED"
            self.conn.execute("UPDATE SimulationRun SET status = 'STOPPED', updated_at = ? WHERE status IN ('RUNNING', 'PAUSED')", (ts,))
        elif action == "RESET":
            self.STATE["range_status"] = "READY"
            self.STATE["active_run_id"] = None
            self.conn.execute("UPDATE SimulatedEndpoint SET status = 'NORMAL', last_event_id = NULL, last_scenario_id = NULL, updated_at = ?", (ts,))
            self.conn.execute("DELETE FROM SecurityEvent WHERE environment = 'LAB'")
            self.conn.execute("DELETE FROM NetworkObservation WHERE environment = 'LAB'")
            self.conn.execute("DELETE FROM Detection WHERE environment = 'LAB'")
            self.conn.execute("DELETE FROM Incident WHERE environment = 'LAB'")
            self.conn.execute("DELETE FROM IncidentEvidence WHERE environment = 'LAB'")
            self.conn.execute("DELETE FROM SimulationRun")
        else:
            raise ValueError(f"Unsupported range control action: {action}")

        self.conn.commit()
        log_audit(self.conn, "lab_operator", f"CYBER_RANGE_{action}", "CyberRange", "lab-range-01", "SUCCESS", {"state": self.STATE["range_status"]}, environment="LAB")
        return dict(self.STATE)

    def run_scenario(self, scenario_id_or_code: str, target_endpoint_id: str = "sim-ep-0001", is_replay: bool = False) -> dict:
        if self.STATE["range_status"] == "PAUSED":
            raise RuntimeError("Cyber range is currently PAUSED. Resume or reset before launching a scenario.")

        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM SimulationScenario WHERE scenario_id = ? OR code = ?",
            (scenario_id_or_code, scenario_id_or_code),
        )
        scen_row = cur.fetchone()
        if not scen_row:
            raise ValueError(f"Scenario '{scenario_id_or_code}' not found in safe catalogue.")
        scen = dict(scen_row)

        cur.execute("SELECT * FROM SimulatedEndpoint WHERE endpoint_id = ?", (target_endpoint_id,))
        ep_row = cur.fetchone()
        if not ep_row:
            raise ValueError(f"Simulated endpoint '{target_endpoint_id}' is not registered.")

        t0 = time.perf_counter()
        ts = now_iso()
        run_id = f"run-{uuid.uuid4().hex[:10]}"
        steps = json.loads(scen["steps_json"])

        emitted_event_ids = []
        detection_ids = []
        incidents = []

        self.STATE["range_status"] = "RUNNING"
        self.STATE["active_run_id"] = run_id
        self.STATE["last_scenario_code"] = scen["code"]

        for step in steps:
            ev_input = {
                "device_id": target_endpoint_id,
                "environment": "LAB",
                "source_type": "CYBER_RANGE_EMULATOR_REPLAY" if is_replay else "CYBER_RANGE_EMULATOR",
                "event_type": step["event_type"],
                "app_context": step.get("app_context", "lab.sim.agent"),
                "evidence_class": step.get("evidence_class", "OBSERVED"),
                "summary": f"[DEMO/LAB {'REPLAY' if is_replay else 'EMULATION'}] {scen['name']} on {target_endpoint_id}",
                "payload": step,
            }
            res = self.engine.evaluate_event(ev_input)
            emitted_event_ids.append(res["event_id"])
            for d in res["detections"]:
                detection_ids.append(d["detection_id"])
            if res["incident"]:
                incidents.append(res["incident"])

        ttd_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        new_ep_status = "ALERT" if detection_ids else "BENIGN_VERIFIED"
        containment = "CONTAINED_IN_LAB_POLICY" if detection_ids else "NO_ACTION_NEEDED_BENIGN"

        self.conn.execute(
            """UPDATE SimulatedEndpoint
               SET status = ?, last_event_id = ?, last_scenario_id = ?, updated_at = ?
               WHERE endpoint_id = ?""",
            (new_ep_status, emitted_event_ids[-1] if emitted_event_ids else None, scen["scenario_id"], ts, target_endpoint_id),
        )

        self.conn.execute(
            """INSERT INTO SimulationRun (
                run_id, scenario_id, target_endpoint_id, status, is_replay,
                emitted_event_ids_json, detection_ids_json, time_to_detect_ms,
                containment_outcome, environment, provenance, retention_policy,
                schema_version, created_at, updated_at
            ) VALUES (?, ?, ?, 'COMPLETED', ?, ?, ?, ?, ?, 'LAB', 'cyber_range_runner', '90d_lab', '1.0', ?, ?)""",
            (
                run_id, scen["scenario_id"], target_endpoint_id, 1 if is_replay else 0,
                json.dumps(emitted_event_ids), json.dumps(detection_ids),
                ttd_ms, containment, ts, ts
            ),
        )
        self.STATE["range_status"] = "READY"
        self.conn.commit()

        log_audit(
            self.conn, "lab_operator", "RUN_SAFE_SCENARIO", "SimulationRun", run_id, "SUCCESS",
            {"scenario": scen["code"], "endpoint": target_endpoint_id, "is_replay": is_replay, "detections": len(detection_ids), "ttd_ms": ttd_ms},
            environment="LAB",
        )

        return {
            "run_id": run_id,
            "scenario_id": scen["scenario_id"],
            "scenario_code": scen["code"],
            "scenario_name": scen["name"],
            "target_endpoint_id": target_endpoint_id,
            "is_replay": is_replay,
            "environment": "LAB",
            "label": "DEMO/LAB EMULATION — NOT A LIVE EXPLOIT",
            "emitted_event_ids": emitted_event_ids,
            "detection_ids": detection_ids,
            "incidents": incidents,
            "time_to_detect_ms": ttd_ms,
            "containment_outcome": containment,
            "endpoint_status": new_ep_status,
        }

    def run_full_evaluation_suite(self) -> dict:
        """Executes all 10 ground-truth labeled scenarios across distinct simulated endpoints and computes actual Precision, Recall, F1, FPR, and latency."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM SimulationScenario ORDER BY scenario_id ASC")
        scenarios = [dict(r) for r in cur.fetchall()]

        tp = fp = tn = fn = 0
        latencies = []
        contained_count = 0
        positive_scenarios = 0
        per_scenario_results = []

        for idx, scen in enumerate(scenarios, start=1):
            ep_id = f"sim-ep-{idx:04d}"
            run_out = self.run_scenario(scen["scenario_id"], target_endpoint_id=ep_id, is_replay=False)
            detected = len(run_out["detection_ids"]) > 0
            expected = bool(scen["expected_detection"])
            latencies.append(run_out["time_to_detect_ms"])

            if expected:
                positive_scenarios += 1
                if detected:
                    tp += 1
                    contained_count += 1
                    outcome_label = "TRUE_POSITIVE"
                else:
                    fn += 1
                    outcome_label = "FALSE_NEGATIVE"
            else:
                if detected:
                    fp += 1
                    outcome_label = "FALSE_POSITIVE"
                else:
                    tn += 1
                    outcome_label = "TRUE_NEGATIVE"

            per_scenario_results.append({
                "scenario_id": scen["scenario_id"],
                "code": scen["code"],
                "name": scen["name"],
                "target_endpoint_id": ep_id,
                "ground_truth_malicious": expected,
                "detected": detected,
                "outcome": outcome_label,
                "time_to_detect_ms": run_out["time_to_detect_ms"],
                "detection_ids": run_out["detection_ids"],
            })

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        mean_ttd = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        containment_rate = round(contained_count / positive_scenarios, 4) if positive_scenarios > 0 else 0.0

        eval_id = f"eval-{uuid.uuid4().hex[:10]}"
        ts = now_iso()
        conditions = (
            "Measured on ADONAI 10-scenario safe cyber-range benchmark (9 malicious/risky emulations + 1 benign trusted-family control) "
            "using SQLite WAL persistence and deterministic 10-layer detection engine."
        )
        self.conn.execute(
            """INSERT INTO EvaluationResult (
                eval_id, suite_name, total_scenarios, true_positives, false_positives,
                true_negatives, false_negatives, precision_score, recall_score,
                f1_score, false_positive_rate, mean_ttd_ms, containment_rate,
                test_conditions, details_json, environment, provenance,
                retention_policy, schema_version, created_at, updated_at
            ) VALUES (?, 'ADONAI Pilot 10-Scenario Ground-Truth Benchmark', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'LAB', 'evaluation_harness', '180d_eval', '1.0', ?, ?)""",
            (
                eval_id, len(scenarios), tp, fp, tn, fn,
                precision, recall, f1, fpr, mean_ttd, containment_rate,
                conditions, json.dumps(per_scenario_results), ts, ts
            ),
        )
        self.conn.commit()
        return {
            "eval_id": eval_id,
            "suite_name": "ADONAI Pilot 10-Scenario Ground-Truth Benchmark",
            "total_scenarios": len(scenarios),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "mean_ttd_ms": mean_ttd,
            "containment_rate": containment_rate,
            "test_conditions": conditions,
            "per_scenario": per_scenario_results,
            "created_at": ts,
        }
