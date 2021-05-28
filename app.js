// see https://github.com/mu-semtech/mu-javascript-template for more info

import { app, query, update, errorHandler, sparqlEscapeString, sparqlEscapeUri } from 'mu';


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
app.post('/sessions/role', async function( req, res ) {
  // TODO: check to ensure properties are there

  // figure out the session id
  const sessionUri = req.headers['mu-session-id'];
  const roleId = req.body.data.id;

  // get the session graph uri
  let queryStr = `
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

    SELECT ?account WHERE {
      GRAPH <http://mu.semte.ch/application> {
        ${sparqlEscapeUri(sessionUri)}
          ext:hasAccount
            ?account.
      }
    }`;

  const sessionGraphResults = await query(queryStr);
  // TODO: cope with case where the session does not exist
  const accountUri = sessionGraphResults.results.bindings[0].account.value;
  const accountGraph = accountUri;

  // update the current role

  // remove the old
  await update( `
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    DELETE WHERE {
      GRAPH <http://mu.semte.ch/application> {
        ${sparqlEscapeUri(sessionUri)} ext:hasRole ?role.
      }
    }` );

  // insert the new (even if the old didn't exist)
  await update( `
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    INSERT {
      GRAPH <http://mu.semte.ch/application> {
        ${sparqlEscapeUri(sessionUri)} ext:hasRole ?role.
      }
    } WHERE {
      GRAPH <http://mu.semte.ch/application> {
        ?role mu:uuid ${sparqlEscapeString(roleId)};
              a ext:Role.
      }
    }`);

  // reset cache key headers
  res.set('mu-auth-allowed-groups', 'CLEAR');
  res.send(204);
});

app.use(errorHandler);
