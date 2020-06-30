from arguments import graphql_authorization

graphql_url = "https://api.github.com/graphql"

headers_graphql = {
 'Accept': 'application/vnd.github.vixen-preview',
 'Authorization': 'bearer %s' % (graphql_authorization),
}



