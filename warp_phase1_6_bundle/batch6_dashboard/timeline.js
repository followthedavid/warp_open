export class Timeline {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.events = [];
        this.selection = null;
    }

    addEvent(evt) { 
        this.events.push(evt); 
        this.render(); 
    }

    render() {
        this.container.innerHTML = '';
        if (this.events.length === 0) return;

        const maxTime = Math.max(...this.events.map(e => e.timestamp));
        const minTime = Math.min(...this.events.map(e => e.timestamp));
        const width = this.container.offsetWidth || 800;
        
        this.events.forEach((evt, idx) => {
            const pos = this.events.length === 1 
                ? width / 2 
                : ((evt.timestamp - minTime) / (maxTime - minTime || 1)) * width;
            
            const div = document.createElement('div');
            div.className = 'evt';
            div.style.left = pos + 'px';
            div.title = `${evt.phase}: ${evt.desc}`;
            div.dataset.index = idx;
            
            div.addEventListener('click', () => {
                console.log('Event clicked:', evt);
            });
            
            this.container.appendChild(div);
        });
    }

    enableSelection() {
        let startX = 0;
        let selectionDiv = null;

        this.container.addEventListener('mousedown', (e) => { 
            if (e.target.classList.contains('evt')) return; // Don't select if clicking event
            startX = e.offsetX; 
            
            selectionDiv = document.createElement('div');
            selectionDiv.className = 'selection';
            selectionDiv.style.left = startX + 'px';
            selectionDiv.style.width = '0px';
            this.container.appendChild(selectionDiv);
        });

        this.container.addEventListener('mousemove', (e) => {
            if (!selectionDiv) return;
            const currentX = e.offsetX;
            const width = Math.abs(currentX - startX);
            const left = Math.min(startX, currentX);
            selectionDiv.style.left = left + 'px';
            selectionDiv.style.width = width + 'px';
        });

        this.container.addEventListener('mouseup', (e) => {
            if (!selectionDiv) return;
            const endX = e.offsetX;
            this.selection = [Math.min(startX, endX), Math.max(startX, endX)];
            console.log('Selection:', this.selection);
            
            // Remove selection visual after a moment
            setTimeout(() => {
                if (selectionDiv && selectionDiv.parentNode) {
                    selectionDiv.parentNode.removeChild(selectionDiv);
                }
                selectionDiv = null;
            }, 1000);
        });
    }

    clear() {
        this.events = [];
        this.container.innerHTML = '';
    }
}
