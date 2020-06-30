import requests
import json
import pandas
import sys

if len(sys.argv) != 4:
    print('Usage: python3 get_security_alerts.py <Github API key> <repository owner> <repository name>')
    exit()

graphql_authorization = sys.argv[1]
repository_owner = sys.argv[2]
repository_name = sys.argv[3]

graphql_url = "https://api.github.com/graphql"
headers_graphql = {
 'Accept': 'application/vnd.github.vixen-preview',
 'Authorization': 'bearer %s' % (graphql_authorization),
}
cursor_value = "first:100"
has_next_page = True

query = """
    {
      repository(owner:"%s", name:"%s") {
        vulnerabilityAlerts(%s) {
          pageInfo {
              endCursor
              hasNextPage
          }
          nodes {
            id
           vulnerableRequirements
            securityVulnerability {
              package {
                ecosystem
                name
              }
              severity
              firstPatchedVersion {
                identifier
              }

              advisory {
                permalink
                references{
                    url
                }
                identifiers {
                  type
                  value
                }
                severity
                description
                databaseId
                ghsaId
                summary
              }

              updatedAt
              vulnerableVersionRange
            }
          }
        }
      }
    }
    """ % (repository_owner ,repository_name, cursor_value)



def run_query(graphql_authorization,repository_owner,repository_name):

    request = requests.post(graphql_url, json={"query": query}, headers=headers_graphql)
    if request.status_code == 200:
        res = request.json()
        print(res)

        global cursor_value
        cursor_value = (
            'first:100 after:"'
            + res["data"]["repository"]["vulnerabilityAlerts"]["pageInfo"]["endCursor"]
            + '"'
        )
        print(cursor_value)
        global has_next_page
        has_next_page = res["data"]["repository"]["vulnerabilityAlerts"]["pageInfo"][
            "hasNextPage"
        ]
        print(has_next_page)
    else:
        raise Exception(
            "Query failed to run by returning code of {}. {}".format(
                request.status_code, query
            )
        )
    return request.json()

def main():


    while has_next_page is True:
        result = run_query(graphql_authorization,repository_owner,repository_name)
        vulslist = result["data"]["repository"]["vulnerabilityAlerts"]["nodes"]
        
        df = pandas.io.json.json_normalize(vulslist)
        
        print(df['securityVulnerability.package.name'])

        # Sort columns
        colnames = df.columns.tolist()
        colnames.remove('securityVulnerability.package.name')
        colnames.remove('securityVulnerability.package.ecosystem')
        colnames.remove('securityVulnerability.severity')
        colnames.remove('securityVulnerability.advisory.severity')
        colnames.remove('securityVulnerability.advisory.summary')
        colnames.remove('securityVulnerability.vulnerableVersionRange')
        colnames.remove('securityVulnerability.firstPatchedVersion.identifier')

        colnames.insert(1,'securityVulnerability.package.name')
        colnames.insert(2,'securityVulnerability.package.ecosystem')
        colnames.insert(3,'securityVulnerability.severity')
        colnames.insert(4,'securityVulnerability.advisory.severity')
        colnames.insert(5,'securityVulnerability.advisory.summary')
        colnames.insert(6,'securityVulnerability.vulnerableVersionRange')
        colnames.insert(7,'securityVulnerability.firstPatchedVersion.identifier')

        df = df.ix[:,colnames]
        df.to_csv("./out.csv")

if __name__ == "__main__":

    main()
