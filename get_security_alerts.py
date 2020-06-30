import requests
import json
import pandas
from constants import headers_graphql
from constants import graphql_url

has_next_page = True
cursor_value = "first:100"

query = """
    {
      repository(owner:"syuren42", name:"trivy-manager") {
        vulnerabilityAlerts(%s) {
          pageInfo {
              endCursor
              hasNextPage
          }
          nodes {
            id
           vulnerableRequirements
            securityVulnerability {
              severity
              advisory {
                permalink
                references{
                    url
                }
                severity
                description
                databaseId
                ghsaId
                summary
              }
              package {
                ecosystem
                name
              }
              updatedAt
              vulnerableVersionRange
            }
          }
        }
      }
    }
    """ % cursor_value

def run_query():
    request = requests.post(graphql_url, json={"query": query}, headers=headers_graphql)
    if request.status_code == 200:
        res = request.json()

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
        result = run_query()
        vulslist = result["data"]["repository"]["vulnerabilityAlerts"]["nodes"]
        print(vulslist)
        pandas.json_normalize(vulslist).to_csv("./out.csv")

if __name__ == "__main__":
    main()
