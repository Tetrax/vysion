"""
Complete audit service that orchestrates all checks from the legacy code.
"""
import logging
import traceback
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, Any, List, Tuple, Optional

# Import directly from legacy_functions module
from app.audit import legacy_functions
from app.audit.models import AuditOptions, AuditResult

# Set up logger
logger = logging.getLogger(__name__)


def _write_temp_config(file_bytes: bytes) -> Path:
    """Write uploaded config to temporary file."""
    tmp = NamedTemporaryFile(delete=False, suffix=".conf")
    tmp.write(file_bytes)
    tmp.flush()
    tmp.close()  # Close the file handle before returning the path
    return Path(tmp.name)


def _default_wan_selection(
    active_interfaces: Dict[str, Dict[str, Any]],
    zones: Dict[str, Dict[str, Any]],
    sdwan_zones: Dict[str, Dict[str, Any]]
) -> List[str]:
    """Select WAN interfaces by default (those marked as WAN)."""
    selected = [name for name, data in active_interfaces.items() if data.get("role") == "wan"]
    selected += [name for name, data in zones.items() if data.get("is_wan_zone")]
    selected += [name for name, data in sdwan_zones.items() if data.get("is_wan_zone")]
    # Deduplicate while preserving order
    seen = set()
    ordered = []
    for item in selected:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def run_complete_audit(file_bytes: bytes, options: AuditOptions) -> Dict[str, Any]:
    """
    Run complete audit matching the legacy auditer() function exactly.
    Returns all check results for report generation.
    """
    logger.info("Starting complete audit...")
    tmp_path = _write_temp_config(file_bytes)
    logger.info(f"Created temporary config file: {tmp_path}")
    warnings: List[str] = []

    try:
        # Load config
        logger.info("Loading config file...")
        config_lines = legacy_functions.lire_config_fortigate(str(tmp_path))
        logger.info(f"Config loaded: {len(config_lines)} lines")
        
        logger.info("Extracting hostname...")
        hostname = legacy_functions.extraire_hostname(config_lines)
        logger.info(f"Hostname: {hostname}")
        
        logger.info("Extracting version and model...")
        version_fortigate_result, version, model = legacy_functions.extraire_modele_version_fortigate(config_lines)
        logger.info(f"Version: {version}, Model: {model}")

        # Read interfaces and zones
        logger.info("Reading interfaces...")
        active_interfaces = legacy_functions.read_active_interfaces(str(tmp_path))
        logger.info(f"Found {len(active_interfaces)} active interfaces")
        
        logger.info("Reading zones...")
        zones, sdwan_zones = legacy_functions.read_zones(str(tmp_path), active_interfaces)
        logger.info(f"Found {len(zones)} zones and {len(sdwan_zones)} SD-WAN zones")

        # Get selected WAN interfaces
        selected_wan_interfaces = options.wan_interfaces or _default_wan_selection(
            active_interfaces, zones, sdwan_zones
        )
        logger.info(f"Selected WAN interfaces: {selected_wan_interfaces}")

        # ISDB reference lists (hardcoded in legacy code)
        incoming_isdbs = legacy_functions.incoming_isdbs if hasattr(legacy_functions, 'incoming_isdbs') else []
        outgoing_isdbs = legacy_functions.outgoing_isdbs if hasattr(legacy_functions, 'outgoing_isdbs') else []
        logger.info(f"ISDB lists - incoming: {len(incoming_isdbs)}, outgoing: {len(outgoing_isdbs)}")

        # Helper to safely call functions
        def safe_call(func, *args, default=None, progress_msg=""):
            func_name = getattr(func, '__name__', str(func))
            try:
                if progress_msg:
                    logger.info(f"[{progress_msg}] Calling {func_name}...")
                result = func(*args)
                if progress_msg:
                    logger.info(f"[{progress_msg}] {func_name} completed successfully")
                return result
            except Exception as exc:
                error_msg = f"{func_name} failed: {str(exc)}"
                logger.error(f"[{progress_msg}] ERROR in {func_name}: {error_msg}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                warnings.append(error_msg)
                return default

        # Run all checks in the exact order as legacy auditer()
        logger.info("=== Starting audit checks (Progress ~10%) ===")
        vip_any_result, vip_any_conform = safe_call(legacy_functions.verifier_vips_extintf_any, config_lines, default=("", False), progress_msg="10%")
        vs_any_result, vs_any_conform = safe_call(legacy_functions.verifier_vs_extintf_any, config_lines, default=("", False), progress_msg="10%")
        sequence_result, sequence_conform = safe_call(legacy_functions.verifier_usage_by_sequence, config_lines, default=("", False), progress_msg="10%")


        logger.info("=== Progress ~20% ===")
        objets_result, objets_conform, objets_non_utilises = safe_call(
            legacy_functions.detecter_objets_non_utilises, config_lines, default=("", False, {}), progress_msg="20%"
        )

        logger.info("=== Progress ~30% ===")
        guest_result, guest_conform = safe_call(legacy_functions.verifier_compte_guest, config_lines, default=("", False), progress_msg="30%")
        admin_result, admin_conform = safe_call(legacy_functions.verifier_compte_admin, config_lines, default=("", False), progress_msg="30%")
        utilisation_ssl_result, utilisation_ssl_conform = safe_call(
            legacy_functions.verifier_vpn_ssl_utilisation, config_lines, default=("", False), progress_msg="30%"
        )
        all_in_rules_result, all_in_rules_conform, all_in_rules_ids = safe_call(
            legacy_functions.verifier_presence_all_port_dans_regles, config_lines, selected_wan_interfaces, default=("", False, []), progress_msg="30%"
        )

        # Progress ~45%
        logger.info("=== Progress ~45% ===")
        geo_ip_result, geo_ip_conform = safe_call(
            legacy_functions.verifier_utilisation_geo_ip, config_lines, selected_wan_interfaces, default=("", False), progress_msg="45%"
        )
        deny_implicit_result, deny_implicit_conform = safe_call(
            legacy_functions.verifier_logs_deny_implicit, config_lines, default=("", False), progress_msg="45%"
        )
        version_cve_message, version_conform = safe_call(legacy_functions.est_version_concernee_par_cve, version, default=("", False), progress_msg="45%")
        eol_result, eol_conform = safe_call(legacy_functions.verifier_modele_fortigate_eol, model, default=("", None), progress_msg="45%")
        usb_result, usb_conform = safe_call(legacy_functions.verifier_auto_install_usb, config_lines, default=("", False), progress_msg="45%")

        logger.info("=== Progress ~50% ===")
        isdb_result, isdb_conform = safe_call(
            legacy_functions.verifier_presence_isdb, config_lines, selected_wan_interfaces, incoming_isdbs, outgoing_isdbs,
            default=("", False), progress_msg="50%"
        )
        http_https_result, http_https_conform, http_https_enabled_interfaces, interfaces_access_details = safe_call(
            legacy_functions.verifier_http_https_desactive_sur_interfaces_wan, config_lines, selected_wan_interfaces,
            default=("", False, [], {})
        )
        admin_sns_result, admin_sns_conform = safe_call(legacy_functions.verifier_compte_admin_sns, config_lines, default=("", False))
        pki_sns_result, pki_sns_conform = safe_call(legacy_functions.verifier_suppression_compte_pki_sns, config_lines, default=("", False))
        pki_pkisns_result, pki_pkisns_conform = safe_call(legacy_functions.verifier_presence_compte_pki_pkisns, config_lines, default=("", False))

        sync_fortianalyzer_result, sync_fortianalyzer_conform = safe_call(
            legacy_functions.verifier_sync_fortianalyzer, config_lines, default=("", False)
        )
        sync_fortimanager_result, sync_fortimanager_conform = safe_call(
            legacy_functions.verifier_sync_fortimanager, config_lines, default=("", False)
        )
        mfa_result, mfa_conform = safe_call(legacy_functions.verifier_mfa_utilisateurs_admins, config_lines, default=("", False))
        ike_result, ike_conform, ike_list, dh_result, dh_conform, dh_list, algo_result, algo_conform, algo_list = safe_call(
            legacy_functions.verifier_durcissement_vpn_ipsec_split, config_lines,
            default=("", False, [], "", False, [], "", False, [])
        )
        cti_result, cti_conform = safe_call(
            legacy_functions.verifier_presence_cti, config_lines, selected_wan_interfaces, model, default=("", False)
        )

        ldaps_result, ldaps_conform = safe_call(legacy_functions.verifier_ldaps, config_lines, default=("", False))
        sauvegardes_result, sauvegardes_conform = safe_call(
            legacy_functions.verifier_sauvegardes_automatiques, config_lines, default=("", False)
        )
        acces_admin_sns_result, acces_admin_sns_conform = safe_call(
            legacy_functions.verifier_acces_admin_sns_via_loopback, config_lines, default=("", False)
        )
        dns_database_result, dns_database_conform = safe_call(legacy_functions.verifier_dns_database, config_lines, default=("", False))
        sip_alg_result, sip_alg_conform = safe_call(legacy_functions.verifier_sip_alg, config_lines, default=("", False))

        fortisandbox_result, fortisandbox_conform = safe_call(
            legacy_functions.verifier_fortisandbox_cloud, config_lines, options.utm_license, default=("", False)
        )
        anycast_fortiguard_result, anycast_fortiguard_conform = safe_call(
            legacy_functions.verifier_anycast_fortiguard, config_lines, options.utm_license, default=("", False)
        )
        fortiguard_result, fortiguard_conform = safe_call(
            legacy_functions.verifier_mises_a_jour_fortiguard, config_lines, options.utm_license, default=("", False)
        )
        blackhole_result, blackhole_conform = safe_call(
            legacy_functions.verifier_route_blackhole, config_lines, options.mpls_l2l, default=("", False)
        )
        ha_session_pickup_result, ha_session_pickup_conform = safe_call(
            legacy_functions.verifier_ha_session_pickup, config_lines, default=("", False)
        )

        ha_cablage_result, ha_cablage_conform = safe_call(
            legacy_functions.verifier_ha_redundance_cablage, config_lines, options.ha_cabling_redundancy, default=("", False)
        )

        ha_redundance_result, ha_redundance_conform = safe_call(
            legacy_functions.verifier_ha_redundance_interfaces, config_lines, default=("", False)
        )
        ha_override_result, ha_override_conform = safe_call(legacy_functions.verifier_ha_override, config_lines, default=("", False))
        ports_deny_result, ports_deny_conform = safe_call(
            legacy_functions.verifier_ports_deny, config_lines, selected_wan_interfaces, default=("", False)
        )
        sdwan_result, sdwan_conform, sdwan_action_message, missing_sdwan_interfaces = safe_call(
            legacy_functions.verifier_utilisation_sdwan, config_lines, selected_wan_interfaces,
            default=("", False, "", [])
        )
        result_profils, conformity_profils, rule_ids_profils = safe_call(
            legacy_functions.verifier_profils_securite_sur_regles, config_lines, default=("", False, [])
        )

        result_mail_filter, conformity_mail_filter, rule_ids_mail_filter = safe_call(
            legacy_functions.verifier_mail_filter, config_lines, default=("", False, [])
        )
        result_web_filter, conformity_web_filter, non_conforming_web_filter = safe_call(
            legacy_functions.verifier_webfilter_profiles, config_lines, options.utm_license, default=("", False, {})
        )
        av_result, av_conformity, av_non_conforming = safe_call(
            legacy_functions.verifier_antivirus_profiles, config_lines, options.utm_license, default=("", False, {})
        )
        dnsfilter_result, dnsfilter_conformity, dnsfilter_non_conforming = safe_call(
            legacy_functions.verifier_dnsfilter_profiles, config_lines, options.utm_license, model, default=("", False, {})
        )
        ips_result, ips_conformity, ips_non_conforming = safe_call(
            legacy_functions.verifier_ips_profiles, config_lines, options.utm_license, default=("", False, {})
        )

        result_app_control, conformity_app_control, non_conforming_app_control = safe_call(
            legacy_functions.verifier_app_control_profiles, config_lines, options.utm_license, default=("", False, {})
        )
        result_port_https_admin, is_compliant_https = safe_call(
            legacy_functions.verifier_port_https_admin, config_lines, default=("", False)
        )
        modele_FAP_result, modele_FAP_conform, modele_FAP_list = safe_call(
            legacy_functions.check_obsolete_fortiap_devices, config_lines, default=("", False, [])
        )
        ssid_result, ssid_conform, ssid_non_conforming_profiles, profiles_utilises = safe_call(
            legacy_functions.verifier_nombre_ssid_par_profil_wifi, config_lines, default=("", False, {}, {})
        )
        bande_5ghz_result, bande_5ghz_conform, bande_5ghz_non_conform = safe_call(
            legacy_functions.verifier_utilisation_bande_5ghz, config_lines, default=("", False, {})
        )

        darrp_result, darrp_conform, darrp_non_conform = safe_call(
            legacy_functions.verifier_darrp_enable, config_lines, default=("", False, {})
        )
        frequency_handoff_result, frequency_handoff_conform, frequency_handoff_non_conform = safe_call(
            legacy_functions.verifier_frequency_handoff, config_lines, default=("", False, {})
        )
        tim_result, tim_conform, tim_non_conform = safe_call(
            legacy_functions.verifier_tim_enable, config_lines, default=("", False, {})
        )
        results_logs = safe_call(legacy_functions.verifier_logs_par_regle, config_lines, default={"counts": {"all": 0, "disable": 0, "utm": 0}})
        nb_all = results_logs.get("counts", {}).get("all", 0)
        nb_disabled = results_logs.get("counts", {}).get("disable", 0)
        nb_utm = results_logs.get("counts", {}).get("utm", 0)

        # Export admin users
        try:
            users_data = legacy_functions.exporter_utilisateurs_admins(str(tmp_path))
        except Exception:
            users_data = []

        nb_policy_enable, nb_policy_disabled = safe_call(
            legacy_functions.compter_regles_activ_ou_desactiv, config_lines, default=(0, 0)
        )
        from datetime import datetime as dt
        nb_policy_always, nb_policy_schedule_actif, nb_policy_schedule_expire = safe_call(
            legacy_functions.collect_schedule_data, config_lines, dt.today(), default=(0, 0, 0)
        )
        ssl_ssh_result, ssl_ssh_conform, ssl_ssh_non_conforming, rule_ids_ssl_ssh = safe_call(
            legacy_functions.verifier_ssl_ssh_profiles, config_lines, default=("", False, {}, [])
        )
        band_result, band_conform, band_non_conform = safe_call(
            legacy_functions.verifier_band_conformite, config_lines, default=("", False, {})
        )
        channel_result, channel_conform, channel_non_conform = safe_call(
            legacy_functions.verifier_channels_conformite, config_lines, default=("", False, {})
        )
        sgi_result, sgi_conform, sgi_non_conform = safe_call(
            legacy_functions.verifier_short_guard_interval, config_lines, default=("", False, {})
        )

        logger.info("=== Progress ~90% - All checks complete ===")

        logger.info("=== All checks complete, compiling results ===")
        
        # Log any warnings
        if warnings:
            logger.warning(f"Audit completed with {len(warnings)} warnings:")
            for warning in warnings:
                logger.warning(f"  - {warning}")
        else:
            logger.info("Audit completed with no warnings")
        
        # Compile all results
        all_results = {
            "hostname": hostname,
            "version": version,
            "model": model,
            "version_fortigate_result": version_fortigate_result,
            "config_lines": config_lines,  # Needed for Word report
            "active_interfaces": active_interfaces,
            "zones": zones,
            "sdwan_zones": sdwan_zones,
            "selected_wan_interfaces": selected_wan_interfaces,
            # All check results
            "guest_result": guest_result,
            "guest_conform": guest_conform,
            "admin_result": admin_result,
            "admin_conform": admin_conform,
            "usb_result": usb_result,
            "usb_conform": usb_conform,
            "vs_any_result": vs_any_result,
            "vs_any_conform": vs_any_conform,
            "vip_any_result": vip_any_result,
            "vip_any_conform": vip_any_conform,
            "utilisation_ssl_result": utilisation_ssl_result,
            "utilisation_ssl_conform": utilisation_ssl_conform,
            "all_in_rules_result": all_in_rules_result,
            "all_in_rules_conform": all_in_rules_conform,
            "all_in_rules_ids": all_in_rules_ids,
            "geo_ip_result": geo_ip_result,
            "geo_ip_conform": geo_ip_conform,
            "version_cve_message": version_cve_message,
            "version_conform": version_conform,
            "eol_result": eol_result,
            "eol_conform": eol_conform,
            "isdb_result": isdb_result,
            "isdb_conform": isdb_conform,
            "http_https_result": http_https_result,
            "http_https_conform": http_https_conform,
            "http_https_enabled_interfaces": http_https_enabled_interfaces,
            "interfaces_access_details": interfaces_access_details,
            "admin_sns_result": admin_sns_result,
            "admin_sns_conform": admin_sns_conform,
            "pki_sns_result": pki_sns_result,
            "pki_sns_conform": pki_sns_conform,
            "pki_pkisns_result": pki_pkisns_result,
            "pki_pkisns_conform": pki_pkisns_conform,
            "deny_implicit_result": deny_implicit_result,
            "deny_implicit_conform": deny_implicit_conform,
            "sync_fortianalyzer_result": sync_fortianalyzer_result,
            "sync_fortianalyzer_conform": sync_fortianalyzer_conform,
            "sync_fortimanager_result": sync_fortimanager_result,
            "sync_fortimanager_conform": sync_fortimanager_conform,
            "mfa_result": mfa_result,
            "mfa_conform": mfa_conform,
            "ike_result": ike_result,
            "ike_conform": ike_conform,
            "ike_list": ike_list,
            "dh_result": dh_result,
            "dh_conform": dh_conform,
            "dh_list": dh_list,
            "algo_result": algo_result,
            "algo_conform": algo_conform,
            "algo_list": algo_list,
            "cti_result": cti_result,
            "cti_conform": cti_conform,
            "ldaps_result": ldaps_result,
            "ldaps_conform": ldaps_conform,
            "sauvegardes_result": sauvegardes_result,
            "sauvegardes_conform": sauvegardes_conform,
            "objets_result": objets_result,
            "objets_conform": objets_conform,
            "objets_non_utilises": objets_non_utilises,
            "acces_admin_sns_result": acces_admin_sns_result,
            "acces_admin_sns_conform": acces_admin_sns_conform,
            "dns_database_result": dns_database_result,
            "dns_database_conform": dns_database_conform,
            "sip_alg_result": sip_alg_result,
            "sip_alg_conform": sip_alg_conform,
            "fortisandbox_result": fortisandbox_result,
            "fortisandbox_conform": fortisandbox_conform,
            "anycast_fortiguard_result": anycast_fortiguard_result,
            "anycast_fortiguard_conform": anycast_fortiguard_conform,
            "fortiguard_result": fortiguard_result,
            "fortiguard_conform": fortiguard_conform,
            "blackhole_result": blackhole_result,
            "blackhole_conform": blackhole_conform,
            "ha_session_pickup_result": ha_session_pickup_result,
            "ha_session_pickup_conform": ha_session_pickup_conform,
            "ha_cablage_result": ha_cablage_result,
            "ha_cablage_conform": ha_cablage_conform,
            "ha_redundance_result": ha_redundance_result,
            "ha_redundance_conform": ha_redundance_conform,
            "ha_override_result": ha_override_result,
            "ha_override_conform": ha_override_conform,
            "ports_deny_result": ports_deny_result,
            "ports_deny_conform": ports_deny_conform,
            "sdwan_result": sdwan_result,
            "sdwan_conform": sdwan_conform,
            "sdwan_action_message": sdwan_action_message,
            "licence_utm": options.utm_license,
            "result_profils": result_profils,
            "conformity_profils": conformity_profils,
            "rule_ids_profils": rule_ids_profils,
            "result_mail_filter": result_mail_filter,
            "conformity_mail_filter": conformity_mail_filter,
            "rule_ids_mail_filter": rule_ids_mail_filter,
            "result_web_filter": result_web_filter,
            "conformity_web_filter": conformity_web_filter,
            "non_conforming_web_filter": non_conforming_web_filter,
            "av_result": av_result,
            "av_conformity": av_conformity,
            "av_non_conforming": av_non_conforming,
            "dnsfilter_result": dnsfilter_result,
            "dnsfilter_conformity": dnsfilter_conformity,
            "dnsfilter_non_conforming": dnsfilter_non_conforming,
            "ips_result": ips_result,
            "ips_conformity": ips_conformity,
            "ips_non_conforming": ips_non_conforming,
            "result_app_control": result_app_control,
            "conformity_app_control": conformity_app_control,
            "non_conforming_app_control": non_conforming_app_control,
            "result_port_https_admin": result_port_https_admin,
            "is_compliant_https": is_compliant_https,
            "modele_FAP_result": modele_FAP_result,
            "modele_FAP_conform": modele_FAP_conform,
            "modele_FAP_list": modele_FAP_list,
            "ssid_result": ssid_result,
            "ssid_conform": ssid_conform,
            "ssid_non_conforming_profiles": ssid_non_conforming_profiles,
            "profiles_utilises": profiles_utilises,
            "bande_5ghz_result": bande_5ghz_result,
            "bande_5ghz_conform": bande_5ghz_conform,
            "bande_5ghz_non_conform": bande_5ghz_non_conform,
            "darrp_result": darrp_result,
            "darrp_conform": darrp_conform,
            "darrp_non_conform": darrp_non_conform,
            "frequency_handoff_result": frequency_handoff_result,
            "frequency_handoff_conform": frequency_handoff_conform,
            "frequency_handoff_non_conform": frequency_handoff_non_conform,
            "tim_result": tim_result,
            "tim_conform": tim_conform,
            "tim_non_conform": tim_non_conform,
            "nb_all": nb_all,
            "nb_disabled": nb_disabled,
            "nb_utm": nb_utm,
            "users_data": users_data,
            "nb_policy_enable": nb_policy_enable,
            "nb_policy_disabled": nb_policy_disabled,
            "nb_policy_always": nb_policy_always,
            "nb_policy_schedule_actif": nb_policy_schedule_actif,
            "nb_policy_schedule_expire": nb_policy_schedule_expire,
            "ssl_ssh_result": ssl_ssh_result,
            "ssl_ssh_conform": ssl_ssh_conform,
            "ssl_ssh_non_conforming": ssl_ssh_non_conforming,
            "rule_ids_ssl_ssh": rule_ids_ssl_ssh,
            "band_result": band_result,
            "band_conform": band_conform,
            "band_non_conform": band_non_conform,
            "channel_result": channel_result,
            "channel_conform": channel_conform,
            "channel_non_conform": channel_non_conform,
            "sgi_result": sgi_result,
            "sgi_conform": sgi_conform,
            "sgi_non_conform": sgi_non_conform,
            "sequence_result": sequence_result,
            "sequence_conform": sequence_conform,
            "regle_no_match": options.regle_no_match,
            "client_name": options.client_name,
            "site_name": options.site_name,
            "serial_number": options.serial_number,
            "license_end_date": options.license_end_date,
            "system_uptime": options.system_uptime,
            "warnings": warnings,

        }

        logger.info("Audit results compiled successfully")
        return all_results

    except Exception as exc:
        logger.error(f"CRITICAL ERROR in run_complete_audit: {str(exc)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise
    finally:
        # Ensure file is closed before deletion on Windows
        try:
            logger.info(f"Cleaning up temporary file: {tmp_path}")
            tmp_path.unlink(missing_ok=True)
        except PermissionError:
            logger.warning(f"Could not delete temporary file (permission error): {tmp_path}")
            pass
        except Exception as exc:
            logger.warning(f"Error deleting temporary file: {exc}")
            pass
