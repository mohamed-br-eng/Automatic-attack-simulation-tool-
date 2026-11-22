import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { ReactFlow, Background, Controls } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { createApi } from '@/data/api'
import { Empty, ErrorState, Loading } from '@/components/common'
export default function Network() {
  const [api] = useState(() => createApi())
  const query = useQuery({
    queryKey: ['topology'],
    queryFn: ({ signal }) => api.getTopology(signal),
    retry: 1,
  })
  return (
    <>
      <div className="page-intro">
        <div>
          <h1>Network map</h1>
          <p>
            Topology appears only when a data source provides network nodes and
            edges.
          </p>
        </div>
      </div>
      <section className="panel">
        {query.isPending ? (
          <Loading />
        ) : query.error ? (
          <ErrorState
            error={query.error}
            retry={() => {
              void query.refetch()
            }}
          />
        ) : !query.data?.nodes.length ? (
          <Empty
            title="No network data available"
            detail="P4 JSON reports do not contain topology. Connect P1/P2 network data to enable this map."
          />
        ) : (
          <div
            className="network-canvas"
            role="region"
            aria-label="Network topology"
          >
            <ReactFlow
              nodes={query.data.nodes.map((n) => ({
                id: n.id,
                data: { label: n.label },
                position: { x: n.x, y: n.y },
              }))}
              edges={query.data.edges}
              fitView
              colorMode="dark"
              nodesDraggable={false}
              nodesConnectable={false}
              edgesFocusable
            >
              <Background />
              <Controls showInteractive={false} />
            </ReactFlow>
          </div>
        )}
      </section>
    </>
  )
}
