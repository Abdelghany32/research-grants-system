#!/usr/bin/env python3
"""Render the reviewed report source. Requires reportlab and pillow in an isolated Python environment."""
from pathlib import Path
import json,re,html
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,Image,Preformatted,KeepInFrame
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing,Rect,String,Line
root=Path(__file__).resolve().parents[1]
for name,file in [('Body','DejaVuSans.ttf'),('Bold','DejaVuSans-Bold.ttf'),('Mono','DejaVuSansMono.ttf')]:
    pdfmetrics.registerFont(TTFont(name,'/usr/share/fonts/truetype/dejavu/'+file))
pdfmetrics.registerFontFamily('Body',normal='Body',bold='Bold',italic='Body',boldItalic='Bold')
navy=colors.HexColor('#132D40');teal=colors.HexColor('#186B68');gray=colors.HexColor('#52616C')
W,H=A4; margin=43; width=W-2*margin
styles={
 'p':ParagraphStyle('p',fontName='Body',fontSize=9.4,leading=13.5,spaceAfter=8,textColor=navy),
 'h':ParagraphStyle('h',fontName='Bold',fontSize=19,leading=23,spaceAfter=17,textColor=navy),
 'sub':ParagraphStyle('sub',fontName='Bold',fontSize=10.5,leading=14,spaceBefore=9,spaceAfter=7,textColor=teal),
 'cell':ParagraphStyle('cell',fontName='Body',fontSize=7.7,leading=10.6,textColor=navy),
 'th':ParagraphStyle('th',fontName='Bold',fontSize=7.7,leading=10.6,textColor=colors.white),
 'code':ParagraphStyle('code',fontName='Mono',fontSize=6.6,leading=10,spaceAfter=10),
}
def inline(t):
    t=t.replace('—','-').replace('–','-').replace('‑','-').replace('∈','in')
    t=html.escape(t)
    t=re.sub(r'`([^`]+)`',r'<font name="Mono">\1</font>',t)
    t=re.sub(r'\*\*([^*]+)\*\*',r'<b>\1</b>',t)
    t=re.sub(r'\*([^*]+)\*',r'<i>\1</i>',t)
    return t

def erd():
    d=Drawing(width,200)
    boxes=[('users',10,145,['PK id','UK email; role']),('grant_calls',190,145,['PK id; FK created_by','budget; currency']),('audit_events',370,145,['PK id; FK actor_id','action; outcome']),('proposals',190,65,['PK id; FK call_id, owner_id','title; amount; status']),('reviews',10,0,['PK id; FK proposal_id','FK reviewer_id, assigned_by']),('decisions',370,0,['PK id; FK proposal_id UK','FK decided_by; award'])]
    def line(x1,y1,x2,y2,label,lx,ly):
        d.add(Line(x1,y1,x2,y2,strokeColor=teal)); d.add(String(lx,ly,label,fontName='Body',fontSize=7,fillColor=teal))
    line(140,165,190,165,'1 : many',143,173)
    line(255,145,255,115,'1 : many',265,128)
    line(75,145,210,115,'1 : many owns',75,121)
    line(140,25,190,80,'many : 1',143,48)
    line(320,80,370,25,'1 : 0..1',330,50)
    line(140,190,370,190,'1 : many (actor optional)',185,193)
    for title,x,y,fields in boxes:
        d.add(Rect(x,y,130,50,fillColor=colors.HexColor('#EFF5F4'),strokeColor=teal,strokeWidth=.7))
        d.add(String(x+7,y+35,title,fontName='Bold',fontSize=9,fillColor=navy))
        for i,f in enumerate(fields):d.add(String(x+7,y+21-i*10,f,fontName='Body',fontSize=6.8,fillColor=navy))
    return d

def parse(body):
    out=[];lines=body.splitlines();i=0
    while i<len(lines):
        l=lines[i].strip()
        if not l:i+=1;continue
        if l=='[ERD]':out.extend([erd(),Spacer(1,10)]);i+=1;continue
        if l.startswith('[SCREENSHOT:'):
            path=root/'docs/evidence/screenshots'/l[len('[SCREENSHOT:'):-1]
            if path.name=='15-auditor-timeline-desktop.png':
                from PIL import Image as PILImage
                crop=root/'tmp/pdfs/audit-excerpt.png'
                with PILImage.open(path) as original: original.crop((0,0,1280,1000)).save(crop)
                path=crop
            im=Image(str(path));scale=min(width/im.imageWidth,235/im.imageHeight)
            im.drawWidth=im.imageWidth*scale;im.drawHeight=im.imageHeight*scale
            out.extend([im,Spacer(1,10)]);i+=1;continue
        if l.startswith('```'):
            i+=1;buf=[]
            while i<len(lines) and not lines[i].startswith('```'):buf.append(lines[i]);i+=1
            code='\n'.join(buf).replace('─','-').replace('▶','>').replace('│','|')
            out.append(Preformatted(code,styles['code'],maxLineLength=112));i+=1;continue
        if l.startswith('|'):
            rows=[]
            while i<len(lines) and lines[i].strip().startswith('|'):
                raw=lines[i].strip().strip('|'); cells=[c.strip() for c in re.split(r'\s*\|\s*',raw)]
                if not all(re.fullmatch(r'[:\- ]+',c) for c in cells): rows.append(cells)
                i+=1
            n=max(map(len,rows));rows=[r+['']*(n-len(r)) for r in rows]
            # Prefer generous explanatory columns; matrices remain balanced.
            weights=[1]*n
            if n==3:weights=[1,1.5,1.5]
            if n==4:weights=[1,1.4,1.6,1.6]
            if rows[0][0]=='#':weights=[.3,1.1,1.7,1.9]
            if n==5:weights=[1,0.5,1,2,2]
            if rows[0][0]=='Capability':weights=[2.8,1,1,1,1]
            if n==6:weights=[.45,.8,1,1.2,1,1.7]
            if n==7:weights=[1.1,.8,.8,1,1.2,.8,.8]
            cw=[width*v/sum(weights) for v in weights]
            cells=[[Paragraph(inline(c),styles['th' if ri==0 else 'cell']) for c in row] for ri,row in enumerate(rows)]
            t=Table(cells,colWidths=cw,repeatRows=1,hAlign='LEFT')
            t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),navy),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#EFF4F3'),colors.white]),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),('LINEBELOW',(0,0),(-1,0),.7,teal)]))
            out.extend([t,Spacer(1,10)]);continue
        if l.startswith('- ') or re.match(r'^\d+\. ',l):
            buf=[l];i+=1
            while i<len(lines) and lines[i].strip() and not lines[i].startswith(('#','|','```','- ')) and not re.match(r'^\d+\. ',lines[i]):
                buf.append(lines[i].strip());i+=1
            out.append(Paragraph(inline(' '.join(buf)),styles['p']));continue
        if l.startswith('###'):
            out.append(Paragraph(inline(l.lstrip('# ').strip()),styles['sub']));i+=1;continue
        buf=[l];i+=1
        while i<len(lines) and lines[i].strip() and not lines[i].startswith(('#','|','```','[SCREENSHOT','[ERD]')):
            buf.append(lines[i].strip());i+=1
        text=' '.join(buf)
        out.append(Paragraph(inline(text),styles['p']))
    return out

def footer(canvas,doc):
    canvas.setStrokeColor(teal);canvas.setLineWidth(.6);canvas.line(margin,39,W-margin,39)
    canvas.setFont('Body',7);canvas.setFillColor(gray)
    canvas.drawString(margin,27,'UNIVERSITY RESEARCH GRANTS  |  Security assessment  |  11 November 2026')
    canvas.drawRightString(W-margin,27,str(doc.page))
    if doc.page>1:
        canvas.setFont('Body',7);canvas.drawString(margin,H-27,'DATABASE SECURITY ENGINEERING')
pages=json.loads((root/'docs/report-pages.json').read_text());story=[]
for i,page in enumerate(pages):
    if i:story.append(PageBreak())
    content=[Paragraph(inline(page['title']),styles['h'])]+parse(page['body'])
    story+=content
out=root/'output/pdf/university-grants-security-report.pdf';out.parent.mkdir(parents=True,exist_ok=True)
SimpleDocTemplate(str(out),pagesize=A4,rightMargin=margin,leftMargin=margin,topMargin=49,bottomMargin=52,title='University Research Grant Management System Security Assessment',author='Database Security Engineering Project Team').build(story,onFirstPage=footer,onLaterPages=footer)
print(out)
