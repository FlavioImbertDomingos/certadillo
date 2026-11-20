/*
 * ServiceNow server script: send an approved "Certadillo application" catalog
 * request to Certadillo.
 *
 * Use it as the script of a Flow Designer action (or a business rule on
 * sc_req_item, after update, when approval changes to "approved") for the
 * catalog item described in README.md. It expects:
 *   - a Connection & Credential alias "x_certadillo.api" holding the base URL
 *     (https://pki.bank.example) and an API key credential with the key of the
 *     Certadillo operator principal "servicenow" (sent as X-API-Key);
 *   - the catalog variables named in README.md.
 *
 * Certadillo answers with the app it created and writes its own decisions back
 * to this RITM as work notes; nothing here needs to poll.
 */
(function sendToCertadillo(ritm) {
    var v = ritm.variables;
    var approver = new GlideRecord('sysapproval_approver');
    approver.addQuery('sysapproval', ritm.getUniqueValue());
    approver.addQuery('state', 'approved');
    approver.orderByDesc('sys_updated_on');
    approver.setLimit(1);
    approver.query();
    var approvedBy = approver.next() ? approver.approver.email.toString() : '';

    var body = {
        ritm: ritm.getValue('number'),
        sys_id: ritm.getUniqueValue(),
        requested_for: ritm.requested_for.email.toString(),
        team: v.certadillo_team.toString(),
        app_name: v.certadillo_app_name.toString(),
        environment: v.certadillo_environment.toString(),
        profile: v.certadillo_profile.toString(),
        allowed_domains: v.certadillo_domains.toString().split(/[\s,]+/).filter(function (d) { return d; }),
        data_classification: v.certadillo_classification.toString() || 'internal',
        snow_approval: {state: 'approved', approved_by: approvedBy, approved_at: new GlideDateTime().getValue()}
    };

    var rm = new sn_ws.RESTMessageV2();
    rm.setHttpMethod('post');
    rm.setEndpoint(sn_cc.ConnectionInfoProvider.getConnectionInfo('x_certadillo.api').getAttribute('connection_url')
        + '/api/v1/integrations/servicenow/onboarding');
    rm.setAuthenticationProfile('api_key', 'x_certadillo.api');
    rm.setRequestHeader('Content-Type', 'application/json');
    rm.setRequestBody(JSON.stringify(body));
    var res = rm.execute();
    if (res.getStatusCode() !== 200) {
        ritm.work_notes = '[Certadillo] request refused (HTTP ' + res.getStatusCode() + '): ' + res.getBody();
        ritm.update();
        gs.error('Certadillo onboarding for ' + body.ritm + ' failed: ' + res.getBody());
    }
})(current);
