import _ from 'lodash';
import PropTypes from 'prop-types';
import React from 'react';
import { withContext } from './util/AppContext.jsx';
import 'whatwg-fetch';
import Vizceral from 'vizceral-react';
import 'vizceral-react/dist/vizceral.css';
import * as d3 from 'd3';

class NetworkGraph extends React.Component {
  static defaultProps = {
    namespace: 'default',
    deployments: []
  }

  static propTypes = {
    namespace: PropTypes.string,
    deployments: PropTypes.array
  }

  constructor(props) {
    super(props);
    this.api = this.props.api;
    this.handleApiError = this.handleApiError.bind(this);
    this.loadFromServer = this.loadFromServer.bind(this);

    this.state = {
      pollingInterval: 5000,
      nodes: [],
      links: [],
      pendingRequests: false,
      loaded: false,
      error: ''
    }
  }

  componentDidMount() {
    this.loadFromServer();
    this.timerId = window.setInterval(this.loadFromServer, this.state.pollingInterval);
  }

  componentWillUnmount() {
    window.clearInterval(this.timerId);
    this.api.cancelCurrentRequests();
  }

  loadFromServer() {
    if (this.state.pendingRequests) {
      return; // don't make more requests if the ones we sent haven't completed
    }
    this.setState({ pendingRequests: true });

    let deployments = _.sortBy(_.map(this.props.deployments, 'name'));
    let urls = _.map(this.props.deployments, d => {
      return this.api.fetchMetrics(this.api.urlsForResource("deployment", "") + "&to_name=" + d.name)
    })

    this.api.setCurrentRequests(urls);

    Promise.all(this.api.getCurrentPromises())
      .then(results => {
        let links = [];
        let nodeList = [];

        _.map(results, (r, i) => {
          let rows = _.get(r, ["ok", "statTables", 0, "podGroup", "rows"]);
          let dst = deployments[i];
          let src = _.map(rows, row => {
            links.push({
              source: row.resource.name,
              target: dst,
              metrics: {
                normal: row.stats.successCount,
                danger: row.stats.failureCount
              }
            });
            nodeList.push(row.resource.name);
            nodeList.push(dst);
          });
        });

        let nodes = _.map(_.uniq(nodeList), n => {
          return {
            name: n,
            renderer: "focusedChild",
            class: "normal",
            maxVolume: 50000
          };
        });

        let vizceralData = {
          renderer: "region",
          name: "entryNode",
          maxVolume: 50000,
          class: "normal",
          updated: Date.now(),
          nodes: nodes,
          connections: links
        }

        this.setState({
          trafficGraph: vizceralData,
          loaded: true,
          pendingRequests: false,
          error: ''
        });
      })
      .catch(this.handleApiError);
  }

  handleApiError(e) {
    if (e.isCanceled) {
      return;
    }

    this.setState({
      pendingRequests: false,
      error: `Error getting data from server: ${e.message}`
    });
  }

  render() {
    return (
      <div style={{height: "500px"}}>
        {this.props.namespace}
        <Vizceral traffic={this.state.trafficGraph}
          showLabels={true}
          viewChanged={view => {}}
          viewUpdated={view => {}}
          objectHighlighted={object => {}}
          nodeContextSizeChanged={dimensions => {}}
          allowDraggingOfNodes={false}
        />
      </div>
    );
  }
}

export default withContext(NetworkGraph);
