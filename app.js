// see https://github.com/mu-semtech/mu-javascript-template for more info

import { app, errorHandler, sparqlEscapeString, sparqlEscapeUri } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';

async function accountForSessionUri(sessionUri) {
  // get the session graph uri
  let queryStr = `
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

    SELECT ?account WHERE {
      GRAPH ?account {
        ${sparqlEscapeUri(sessionUri)}
          ext:hasAccount
            ?account.
      }
    }`;

  const sessionGraphResults = await query(queryStr);
  // TODO: cope with case where the session does not exist
  return sessionGraphResults.results.bindings[0].account.value;
}

/**
 * POST /sessions/role
 *
 * Selects a new role.
 *
 * Body
 * data: {
 *   type: "roles",
 *   id: "uuid"
 * }
 */
app.post('/session/role', async function(req, res) {
  try {
    // figure out the session id
    const sessionUri = req.headers['mu-session-id'];
    const roleId = req.body.data.id;

    const accountUri = await accountForSessionUri(sessionUri);
    const accountGraph = accountUri;

    // update the current role

    // remove the old
    await update(`
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    DELETE WHERE {
      GRAPH ${sparqlEscapeUri(accountGraph)} {
        ${sparqlEscapeUri(sessionUri)} ext:hasRole ?role.
      }
    }`);

    // insert the new (even if the old didn't exist)
    await update(`
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    INSERT {
      GRAPH ${sparqlEscapeUri(accountGraph)} {
        ${sparqlEscapeUri(sessionUri)} ext:hasRole ?role.
      }
    } WHERE {
      GRAPH ${sparqlEscapeUri(accountGraph)} {
        ?role mu:uuid ${sparqlEscapeString(roleId)};
              a ext:Role.
      }
    }`);

    // reset cache key headers
    res.set('mu-auth-allowed-groups', 'CLEAR');
    res.send(204);
  } catch (e) {
    res.status(503).send({
      message: "Something went wrong while switching the session"
    });
  }
});

app.get('/session/roles', async function(req, res) {
  try {
    const sessionUri = req.headers['mu-session-id'];
    const accountUri = await accountForSessionUri(sessionUri);
    const accountGraph = accountUri;

    const queryResults = await query(`
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX adres: <https://data.vlaanderen.be/ns/adres#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

    SELECT ?role ( MAX(?roleId) AS ?roleId ) ( MAX(?roleType) AS ?roleType ) (GROUP_CONCAT(DISTINCT ?poiName ; separator=", ") AS ?poiNames) {
      GRAPH ${sparqlEscapeUri(accountGraph)} {
        ${sparqlEscapeUri(accountUri)}
          a foaf:OnlineAccount;
          ext:hasRole ?role.
        ?role a ext:Role, ?roleType;
          mu:uuid ?roleId.
        FILTER( ?roleType != ext:Role )
      }

      OPTIONAL {
         GRAPH ${sparqlEscapeUri(accountGraph)} {
           ?role ext:actsOn ?poi.
         }
        GRAPH ?museumGraph {
          ?poi
            a adres:AdresseerbaarObject;
            mu:uuid ?uuid;
            rdfs:label ?poiName.
        }
      }
    } GROUP BY ?role
  `);

    res
      .status(200)
      .send(JSON.stringify({
        data: queryResults.results.bindings.map((bindings) => {
          const type = bindings.roleType.value
                === "http://mu.semte.ch/vocabularies/ext/ValidatorRole"
                ? "validator-roles"
                : "data-entry-roles";
          return {
            attributes: {
              concatenatedPoiName: type === "data-entry-roles" ? bindings.poiNames.value : undefined
            },
            id: bindings.roleId.value,
            type: type
          };
        })
      }));
  } catch (e) {
    res
      .status(500)
      .send(JSON.stringify({
        message: "something went wrong while listing roles"
      }));
  }
});

app.use(errorHandler);
